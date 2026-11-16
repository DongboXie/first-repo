#!/usr/bin/env python3
"""分析 UPC2030 流水线，并协调模型在本地隔离分支中生成源码修复。"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


# 本文件既可作为脚本执行，也会被单元测试按文件加载；显式加入同级目录以加载 SDK 适配模块。
AGENT_MODULE_ROOT = str(Path(__file__).resolve().parent)
if AGENT_MODULE_ROOT not in sys.path:
    sys.path.insert(0, AGENT_MODULE_ROOT)

from claude_analysis import analyze_with_claude
from patch_suggestions import build_patch_artifacts


REPORT_SCHEMA = "upc2030-agent-analysis-v1"
ENGINE = "deterministic_rules_v1"
MAX_FINDINGS = 100
MAX_EVIDENCE_CHARS = 600
MAX_LOG_BYTES = 20 * 1024 * 1024
REPAIR_PLAN_SCHEMA = "upc2030-agent-repair-plan-v1"

REPORT_SPECS: tuple[dict[str, Any], ...] = (
    {
        "stage": "sync",
        "file": "repo_sync_report.json",
        "schema": None,
        "category": "repository_sync",
        "optional": False,
        "requires_finalized": False,
    },
    {
        "stage": "prepare_workspace",
        "file": "workspace_prepare_report.json",
        "schema": "upc2030-workspace-prepare-report-v1",
        "category": "configuration",
        "optional": False,
        "requires_finalized": True,
    },
    {
        "stage": "static_check",
        "file": "static_check_report.json",
        "schema": "upc2030-static-check-report-v1",
        "category": "static_analysis",
        "optional": True,
        "requires_finalized": True,
    },
    {
        "stage": "build",
        "file": "build_report.json",
        "schema": "upc2030-build-report-v1",
        "category": "build",
        "optional": False,
        "requires_finalized": True,
    },
    {
        "stage": "validate_artifacts",
        "file": "artifact_validation_report.json",
        "schema": "upc2030-artifact-validation-report-v1",
        "category": "artifact",
        "optional": False,
        "requires_finalized": True,
    },
    {
        "stage": "hil_check",
        "file": "hil_check_report.json",
        "schema": "upc2030-hil-check-report-v1",
        "category": "hardware_test",
        "optional": False,
        "requires_finalized": True,
    },
    {
        "stage": "package",
        "file": "package_report.json",
        "schema": "upc2030-package-report-v1",
        "category": "package",
        "optional": False,
        "requires_finalized": True,
    },
    {
        "stage": "publish",
        "file": "seafile_publish_report.json",
        "schema": "upc2030-seafile-publish-report-v1",
        "category": "publish",
        "optional": False,
        # 现有发布报告没有 finalized 字段，直接使用 status 判定。
        "requires_finalized": False,
    },
)

COMPILER_DIAGNOSTIC = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+):\s*"
    r"(?P<kind>fatal error|error|warning):\s*(?P<message>.+)$",
    re.IGNORECASE,
)
GCC_NUMBERED_SOURCE_LINE = re.compile(
    r"^\s*(?P<line>\d+)\s*\|(?P<separator> ?)(?P<source>.*)$"
)
WINDOWS_PROCESS_ERROR = re.compile(r"CreateProcessW|make\s*\(e=87\)|Error\s+87", re.IGNORECASE)
LINKER_ERROR = re.compile(
    r"undefined reference to|cannot find -l|region .+ overflowed|collect2(?:\.exe)?: error",
    re.IGNORECASE,
)
TOOLCHAIN_ERROR = re.compile(
    r"Java was started but returned exit code|cannot run program|is not recognized as|No such file or directory",
    re.IGNORECASE,
)

RECOMMENDATIONS = {
    "source_code": "根据文件、行号和编译器消息修复源码，然后在同一 MR 中重新运行流水线。",
    "runner_environment": "保留失败日志并检查 Windows Runner 残留进程、服务状态和 STM32CubeIDE External Builder；不要直接修改业务源码。",
    "linker": "检查链接脚本、库搜索路径、缺失符号和目标配置是否与当前 Snapshot 一致。",
    "toolchain": "检查 Runner 上 STM32CubeIDE、Java、GNU 工具链路径和服务账户环境。",
    "repository_sync": "检查 MR/Change Set、仓库权限和引用是否存在，再重新执行同步。",
    "configuration": "检查 CI 变量、env.yaml 和 .cproject 配置，避免修改无关源码。",
    "artifact": "核对构建报告中的必需文件、大小和 SHA-256，不要发布未通过校验的制品。",
    "package": "检查打包输入和清单，确认所有必需制品来自同一 Snapshot。",
    "publish": "检查 Seafile 地址、目录权限和鉴权配置；已经生成的固件无需重新编译。",
    "static_analysis": "根据静态检查报告修复问题；当前能力未启用时应保持 skipped/not_run。",
    "hardware_test": "检查板卡、烧录、连接和测试脚本；HIL 是发布前的强制门禁。",
    "analysis_input": "检查上游 Job 是否按 always 上传 ci_out 报告和日志。",
    "build": "优先查看对应目标日志中的第一条明确错误，再决定修改源码、配置或 Runner。",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(text: str) -> str:
    """对可能出现在日志证据中的 URL 凭据和常见密钥赋值进行脱敏。"""
    value = re.sub(
        r"(?i)(https?://)([^\s/:@]+):([^\s/@]+)@",
        r"\1***:***@",
        str(text),
    )
    value = re.sub(
        r"(?i)\b(token|password|passwd|secret|api[_-]?key)\s*([=:])\s*[^\s]+",
        lambda match: f"{match.group(1)}{match.group(2)}***",
        value,
    )
    return value[:MAX_EVIDENCE_CHARS]


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0:
        raise ValueError("报告不存在、为空或不是普通文件")
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("报告根节点必须是 JSON 对象")
    return payload


def report_status(spec: dict[str, Any], payload: dict[str, Any]) -> tuple[str, list[str]]:
    """校验阶段报告契约并返回归一化状态，防止残缺报告被误判为成功。"""
    errors: list[str] = []
    if spec["stage"] == "sync":
        if payload.get("ok") is not True:
            errors.append(f"仓库同步失败: {payload.get('failure_class') or 'UNKNOWN_FAIL'}")
        return ("success" if not errors else "failed"), errors

    if payload.get("schema") != spec["schema"]:
        errors.append(
            f"报告 schema 不匹配: expected={spec['schema']}, actual={payload.get('schema')}"
        )
    if spec["requires_finalized"] and payload.get("finalized") is not True:
        errors.append("阶段报告 finalized 不是 true")
    if payload.get("status") != "success":
        errors.extend(payload_errors(payload))
        if not errors:
            errors.append(f"阶段报告状态不是 success: {payload.get('status')}")
    return ("success" if not errors else "failed"), errors


def payload_errors(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    errors = payload.get("errors")
    if isinstance(errors, list):
        values.extend(str(item) for item in errors if str(item).strip())
    elif errors:
        values.append(str(errors))
    failure_class = payload.get("failure_class")
    if failure_class:
        values.append(f"failure_class={failure_class}")
    targets = payload.get("targets")
    if isinstance(targets, list):
        for target in targets:
            if not isinstance(target, dict) or target.get("status") == "success":
                continue
            target_id = target.get("id") or "<unknown>"
            target_errors = target.get("errors")
            if isinstance(target_errors, list) and target_errors:
                values.extend(f"{target_id}: {item}" for item in target_errors)
            else:
                values.append(f"{target_id}: status={target.get('status')}")
    return values


def add_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[Any, ...]],
    *,
    severity: str,
    category: str,
    title: str,
    evidence: str,
    stage: str | None = None,
    target: str | None = None,
    file: str | None = None,
    line: int | None = None,
    confidence: str = "medium",
    code: str | None = None,
    source_excerpt: str | None = None,
    source_line: str | None = None,
) -> None:
    if len(findings) >= MAX_FINDINGS:
        return
    key = (severity, category, code, stage, target, file, line, title)
    if key in seen:
        return
    seen.add(key)
    finding = {
            "severity": severity,
            "category": category,
            "code": code,
            "title": title,
            "stage": stage,
            "target": target,
            "file": file,
            "line": line,
            "evidence": redact(evidence),
            "recommendation": RECOMMENDATIONS.get(category, RECOMMENDATIONS["build"]),
            "confidence": confidence,
        }
    if source_excerpt:
        finding["source_excerpt"] = redact(source_excerpt)
    if source_line is not None:
        finding["source_line"] = redact(source_line)
    findings.append(finding)


def compiler_source_context(
    lines: list[str],
    diagnostic_index: int,
    expected_source_line: int,
) -> tuple[str, str | None]:
    """返回诊断及其后续展示行，并提取 GCC 带行号格式中的准确源码文本。"""
    excerpt_end = min(len(lines), diagnostic_index + 4)
    excerpt_lines = lines[diagnostic_index:excerpt_end]
    exact_source_line = None
    for candidate in lines[diagnostic_index + 1 : excerpt_end]:
        displayed = GCC_NUMBERED_SOURCE_LINE.match(candidate)
        if displayed and int(displayed.group("line")) == expected_source_line:
            # GCC 在竖线后固定添加一个展示用空格；只移除该分隔符，保留源码自身缩进。
            exact_source_line = displayed.group("source")
            break
    return "\n".join(excerpt_lines), exact_source_line


def analyze_reports(
    output_root: Path,
    findings: list[dict[str, Any]],
    seen: set[tuple[Any, ...]],
) -> tuple[list[dict[str, Any]], str]:
    inputs: list[dict[str, Any]] = []
    upstream_failed = False
    saw_success = False

    for spec in REPORT_SPECS:
        path = output_root / spec["file"]
        item = {"stage": spec["stage"], "path": spec["file"], "status": "missing", "schema": None}
        if not path.is_file():
            if spec["optional"]:
                item["status"] = "not_run"
            elif upstream_failed:
                item["status"] = "not_run"
            else:
                upstream_failed = True
                add_finding(
                    findings,
                    seen,
                    severity="error",
                    category=spec["category"],
                    code="MISSING_REPORT",
                    title=f"缺少必需阶段报告：{spec['stage']}",
                    evidence=spec["file"],
                    stage=spec["stage"],
                    confidence="high",
                )
            inputs.append(item)
            continue

        try:
            payload = read_json_object(path)
            item["schema"] = payload.get("schema")
            item["status"], validation_errors = report_status(spec, payload)
            if item["status"] == "success":
                saw_success = True
            else:
                upstream_failed = True
                evidence = "；".join(validation_errors[:4])
                add_finding(
                    findings,
                    seen,
                    severity="error",
                    category=spec["category"],
                    code=f"{spec['stage'].upper()}_FAILED",
                    title=f"阶段失败：{spec['stage']}",
                    evidence=evidence,
                    stage=spec["stage"],
                )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            item["status"] = "invalid"
            upstream_failed = True
            add_finding(
                findings,
                seen,
                severity="error",
                category="analysis_input",
                code="INVALID_REPORT",
                title=f"阶段报告无法读取：{spec['stage']}",
                evidence=str(exc),
                stage=spec["stage"],
                confidence="high",
            )
        inputs.append(item)

    if upstream_failed:
        pipeline_status = "failed"
    elif saw_success:
        pipeline_status = "success"
    else:
        pipeline_status = "unknown"
    return inputs, pipeline_status


def analyze_log(
    path: Path,
    findings: list[dict[str, Any]],
    seen: set[tuple[Any, ...]],
) -> dict[str, Any]:
    relative = f"logs/{path.name}"
    result = {"path": relative, "status": "success", "size": None, "lines": 0}
    if path.is_symlink() or not path.is_file():
        result["status"] = "invalid"
        return result
    size = path.stat().st_size
    result["size"] = size
    if size > MAX_LOG_BYTES:
        result["status"] = "too_large"
        add_finding(
            findings,
            seen,
            severity="error",
            category="analysis_input",
            code="LOG_TOO_LARGE",
            title=f"日志超过分析上限：{path.stem}",
            evidence=f"size={size}, limit={MAX_LOG_BYTES}",
            target=path.stem,
        )
        return result

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines()
    result["lines"] = len(lines)
    for line_number, raw_line in enumerate(lines, start=1):
        line_text = raw_line.strip()
        if not line_text:
            continue
        compiler = COMPILER_DIAGNOSTIC.match(line_text)
        if compiler:
            kind = compiler.group("kind").lower()
            severity = "warning" if kind == "warning" else "error"
            source_line_number = int(compiler.group("line"))
            source_excerpt, source_line = compiler_source_context(
                lines,
                line_number - 1,
                source_line_number,
            )
            # 编译器通常会在诊断行后打印源码和指示符；从诊断行开始截取，避免前一行
            # 超长编译命令占满脱敏上限而截掉真正的源码上下文。
            # 该片段随 ci_out Artifact 传递，Agent Job 不需要也不会读取组件工作区。
            add_finding(
                findings,
                seen,
                severity=severity,
                category="source_code",
                code="COMPILER_WARNING" if severity == "warning" else "COMPILER_ERROR",
                title=compiler.group("message"),
                evidence=line_text,
                stage="build",
                target=path.stem,
                file=compiler.group("file"),
                line=source_line_number,
                confidence="high",
                source_excerpt=source_excerpt,
                source_line=source_line,
            )
            continue
        if WINDOWS_PROCESS_ERROR.search(line_text):
            add_finding(
                findings,
                seen,
                severity="error",
                category="runner_environment",
                code="WINDOWS_CREATE_PROCESS_87",
                title="Windows 创建编译子进程失败（Error 87）",
                evidence=line_text,
                stage="build",
                target=path.stem,
                confidence="high",
            )
        elif LINKER_ERROR.search(line_text):
            add_finding(
                findings,
                seen,
                severity="error",
                category="linker",
                code="LINKER_ERROR",
                title="链接阶段错误",
                evidence=line_text,
                stage="build",
                target=path.stem,
                confidence="high",
            )
        elif TOOLCHAIN_ERROR.search(line_text):
            add_finding(
                findings,
                seen,
                severity="error",
                category="toolchain",
                code="TOOLCHAIN_ERROR",
                title="工具链或运行环境错误",
                evidence=line_text,
                stage="build",
                target=path.stem,
                confidence="medium",
            )
    return result


def analyze_logs(
    output_root: Path,
    findings: list[dict[str, Any]],
    seen: set[tuple[Any, ...]],
) -> list[dict[str, Any]]:
    logs_root = output_root / "logs"
    if not logs_root.is_dir() or logs_root.is_symlink():
        return []
    return [analyze_log(path, findings, seen) for path in sorted(logs_root.glob("*.log"))]


def ci_metadata(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    env = os.environ if environ is None else environ
    allowed = (
        "CI_PIPELINE_ID",
        "CI_PIPELINE_URL",
        "CI_PROJECT_PATH",
        "CI_COMMIT_SHA",
        "CI_COMMIT_REF_NAME",
        "CI_PIPELINE_SOURCE",
        "TRIGGER_PROJECT",
        "TRIGGER_MR_IID",
        "TRIGGER_COMMIT_SHA",
        "TRIGGER_REF_PATH",
        "TRIGGER_SOURCE_BRANCH",
        "TRIGGER_SOURCE_BRANCH_SHA",
        "TRIGGER_TARGET_BRANCH",
        "SOURCE_PROJECT",
        "SOURCE_MR_IID",
        "SOURCE_COMMIT_SHA",
        "SOURCE_REF_PATH",
    )
    return {name.lower(): env[name] for name in allowed if env.get(name)}


def _project_key(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip("/").removesuffix(".git").lower()


def repository_context(
    output_root: Path,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a non-secret mapping from the integration SHA to resolved component SHAs."""
    env = os.environ if environ is None else environ
    context: dict[str, Any] = {
        "integration": {
            "project": env.get("CI_PROJECT_PATH"),
            "commit_sha": env.get("CI_COMMIT_SHA"),
            "ref": env.get("CI_COMMIT_REF_NAME"),
        },
        "projects": [],
    }
    sync_report = output_root / "repo_sync_report.json"
    if not sync_report.is_file():
        return context
    try:
        payload = read_json_object(sync_report)
    except (OSError, ValueError, json.JSONDecodeError):
        return context

    active_changes: dict[str, dict[str, Any]] = {}
    changeset_path = output_root / "original_changeset.json"
    if changeset_path.is_file():
        try:
            changeset = read_json_object(changeset_path)
            if (
                changeset.get("schema")
                in {
                    "upc2030-original-changeset-v1",
                    "upc2030-repair-changeset-v1",
                }
                and changeset.get("status") == "discovered"
                and isinstance(changeset.get("changes"), list)
            ):
                context["change_set"] = {
                    "schema": changeset.get("schema"),
                    "change_set_id": changeset.get("change_set_id"),
                    "original_change_set_id": changeset.get("original_change_set_id"),
                    "change_count": changeset.get("change_count"),
                }
                active_changes = {
                    _project_key(change.get("project")): change
                    for change in changeset["changes"]
                    if isinstance(change, dict) and change.get("project")
                }
        except (OSError, ValueError, json.JSONDecodeError):
            # The sync report remains useful for read-only analysis. Exact Change Set
            # validation is enforced earlier by repo_sync.py.
            active_changes = {}

    trigger_key = _project_key(env.get("TRIGGER_PROJECT") or env.get("SOURCE_PROJECT"))
    projects = payload.get("projects") or []
    if not isinstance(projects, list):
        return context
    for project in projects:
        if not isinstance(project, dict):
            continue
        name = str(project.get("name") or "")
        expected = str(project.get("expected") or "")
        item: dict[str, Any] = {
            "project": name,
            "path": project.get("path"),
            "requested_ref": expected or None,
            "resolved_sha": project.get("after_commit"),
            "branch": project.get("branch"),
            "source": project.get("source"),
            "ok": bool(project.get("ok")),
            "is_trigger_project": bool(trigger_key and _project_key(name) == trigger_key),
            "is_changeset_project": _project_key(name) in active_changes,
        }
        active_change = active_changes.get(_project_key(name))
        if active_change is not None:
            ref_path = str(active_change.get("ref_path") or "")
            mode = "merge" if ref_path.endswith("/merge") else "head"
            item.update(
                {
                    "merge_request": {
                        "iid": int(active_change["mr"]),
                        "mode": mode,
                    },
                    "source_branch": active_change.get("source_branch"),
                    "source_branch_sha": active_change.get("commit"),
                    "target_branch": active_change.get("target_branch"),
                    "origin_mr": active_change.get("origin_mr"),
                    "origin_commit": active_change.get("origin_commit"),
                    "origin_source_branch": active_change.get("origin_source_branch"),
                    "origin_target_branch": active_change.get("origin_target_branch"),
                }
            )
        if item["is_trigger_project"]:
            source_branch_sha = env.get("TRIGGER_SOURCE_BRANCH_SHA")
            trigger_ref_path = str(env.get("TRIGGER_REF_PATH") or "")
            if not source_branch_sha and (
                expected.endswith("/head") or trigger_ref_path.endswith("/head")
            ):
                # In detached MR pipelines CI_COMMIT_SHA is the source branch head. In merged
                # result pipelines TRIGGER_SOURCE_BRANCH_SHA must be supplied explicitly.
                source_branch_sha = env.get("TRIGGER_COMMIT_SHA")
            if active_change is None:
                item.update(
                    {
                        "source_branch": env.get("TRIGGER_SOURCE_BRANCH"),
                        "source_branch_sha": source_branch_sha,
                        "target_branch": env.get("TRIGGER_TARGET_BRANCH"),
                    }
                )
        mr_match = re.fullmatch(r"MR!(\d+)/(merge|head)", expected)
        if mr_match and active_change is None:
            item["merge_request"] = {
                "iid": int(mr_match.group(1)),
                "mode": mr_match.group(2),
            }
        context["projects"].append(item)
    return context


def summary_text(pipeline_status: str, findings: list[dict[str, Any]]) -> str:
    errors = sum(item["severity"] == "error" for item in findings)
    warnings = sum(item["severity"] == "warning" for item in findings)
    if pipeline_status == "success" and errors == 0:
        return f"流水线成功；发现 {warnings} 条编译 Warning。" if warnings else "流水线成功，未发现需要处理的问题。"
    if errors:
        primary = next(item for item in findings if item["severity"] == "error")
        return f"流水线存在 {errors} 个错误类发现；首要问题：{primary['title']}。"
    return "现有报告不足，无法确定流水线最终状态。"


def markdown_escape(value: Any) -> str:
    return str(value if value is not None else "-").replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# UPC2030 流水线 Agent 分析报告",
        "",
        f"- 分析引擎：`{report['engine']}`",
        f"- 流水线状态：`{report['pipeline_status']}`",
        f"- 分析状态：`{report['status']}`",
        f"- 结论：{report['summary']}",
        "",
    ]
    repo_context = report.get("repository_context") or {}
    integration = repo_context.get("integration") or {}
    lines.extend(
        [
            "## 仓库版本上下文",
            "",
            f"- 集成仓库：`{markdown_escape(integration.get('project'))}`",
            f"- 集成提交：`{markdown_escape(integration.get('commit_sha'))}`",
            "",
            "| 仓库 | 请求引用 | 实际解析 SHA | MR | 触发仓库 |",
            "|---|---|---|---|---|",
        ]
    )
    for project in repo_context.get("projects") or []:
        merge_request = project.get("merge_request") or {}
        mr_label = (
            f"!{merge_request.get('iid')}/{merge_request.get('mode')}"
            if merge_request.get("iid") is not None
            else "-"
        )
        lines.append(
            f"| {markdown_escape(project.get('project'))} "
            f"| {markdown_escape(project.get('requested_ref'))} "
            f"| {markdown_escape(project.get('resolved_sha'))} "
            f"| {markdown_escape(mr_label)} "
            f"| {'是' if project.get('is_trigger_project') else '否'} |"
        )
    lines.extend(["", "## 发现", ""])
    if not report["findings"]:
        lines.append("未发现错误或 Warning。")
    for finding in report["findings"]:
        location = finding.get("file") or finding.get("target") or finding.get("stage") or "pipeline"
        if finding.get("line") is not None:
            location = f"{location}:{finding['line']}"
        lines.extend(
            [
                f"### [{finding['severity'].upper()}] {finding['title']}",
                "",
                f"- 分类：`{finding['category']}`",
                f"- 位置：`{markdown_escape(location)}`",
                f"- 置信度：`{finding['confidence']}`",
                f"- 证据：`{markdown_escape(finding['evidence'])}`",
                f"- 建议：{finding['recommendation']}",
                "",
            ]
        )

    model_result = report.get("model_analysis") or {}
    lines.extend(["## 模型 Agent 分析（Claude Agent SDK）", ""])
    lines.append(f"- 状态：`{markdown_escape(model_result.get('status', 'not_configured'))}`")
    provider = model_result.get("provider") or {}
    if provider.get("model"):
        lines.append(f"- 模型：`{markdown_escape(provider['model'])}`")
    analysis = model_result.get("analysis")
    if isinstance(analysis, dict):
        root_cause = analysis.get("root_cause") or {}
        lines.extend(
            [
                f"- 总体判断：{markdown_escape(analysis.get('overall_assessment'))}",
                f"- 根因分类：`{markdown_escape(root_cause.get('category'))}`",
                f"- 根因说明：{markdown_escape(root_cause.get('summary'))}",
                f"- 置信度：`{markdown_escape(root_cause.get('confidence'))}`",
                "",
                "### 建议操作",
                "",
            ]
        )
        actions = analysis.get("recommended_actions") or []
        if actions:
            for action in sorted(actions, key=lambda item: item.get("priority", 99)):
                lines.append(
                    f"{action.get('priority', '-')}. {markdown_escape(action.get('action'))}；"
                    f"验证：{markdown_escape(action.get('verification'))}"
                )
        else:
            lines.append("模型未返回建议操作。")
    elif model_result.get("errors"):
        lines.append(f"- 错误：{markdown_escape('；'.join(model_result['errors']))}")
    else:
        lines.append(f"- 说明：{markdown_escape(model_result.get('reason', '本次未调用模型'))}")
    lines.append("")

    patch_plan = report.get("patch_plan") or {}
    patch_source = patch_plan.get("source") or {}
    lines.extend(
        [
            "## Agent 修复建议",
            "",
            f"- 状态：`{markdown_escape(patch_plan.get('status', 'unavailable'))}`",
            f"- 目标仓库：`{markdown_escape(patch_source.get('project'))}`",
            f"- 目标提交：`{markdown_escape(patch_source.get('resolved_sha'))}`",
            f"- 说明：{markdown_escape(patch_plan.get('summary') or '未生成补丁建议')}",
            "- 补丁文件：`suggested.patch`（校验通过后自动发布到隔离的 Draft 修复 MR）",
            "- 合并策略：禁止自动合并，必须由开发者在修复 MR 中审查、批准并点击 Merge",
            "",
        ]
    )
    changes = patch_plan.get("changes") or []
    if changes:
        lines.extend(["### 建议改动", ""])
        for index, change in enumerate(changes, start=1):
            lines.append(
                f"{index}. `{markdown_escape(change.get('file'))}:{markdown_escape(change.get('line'))}` "
                f"{markdown_escape(change.get('operation'))}：{markdown_escape(change.get('description'))}"
            )
        lines.append("")

    lines.extend(["## 输入状态", "", "| 阶段 | 状态 | 报告 |", "|---|---|---|"])
    lines.extend(
        f"| {markdown_escape(item['stage'])} | {markdown_escape(item['status'])} | {markdown_escape(item['path'])} |"
        for item in report["inputs"]["reports"]
    )
    lines.extend(["", "## 限制", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def _analyze_multi_repo_changeset(
    report: dict[str, Any],
    repair_targets: list[dict[str, Any]],
    json_report: Path,
    markdown_report: Path,
    patch_plan_report: Path,
    suggested_patch_report: Path,
    *,
    agent_config: Path | None,
    require_model: bool,
    environ: Mapping[str, str] | None,
    model_runner: Callable[..., dict[str, Any]] | None,
) -> int:
    """Analyze each active Change Set repository in an isolated edit scope."""
    repairs: list[dict[str, Any]] = []
    model_results: list[dict[str, Any]] = []
    patch_outputs: list[tuple[Path, str]] = []

    for target in repair_targets:
        scoped_report = copy.deepcopy(report)
        target_key = _project_key(target.get("project"))
        for project in scoped_report["repository_context"]["projects"]:
            if isinstance(project, dict):
                project["is_trigger_project"] = (
                    _project_key(project.get("project")) == target_key
                )
        model_result = analyze_with_claude(
            scoped_report,
            agent_config,
            environ=environ,
            runner=model_runner,
            cwd=Path.cwd(),
        )
        child_plan, child_patch = build_patch_artifacts(
            scoped_report,
            model_result,
            workspace_root=Path.cwd(),
        )
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", target_key).strip("-") or "repository"
        patch_path = patch_plan_report.parent / "suggested_patches" / f"{slug}.patch"
        repairs.append(
            {
                "project": target.get("project"),
                "patch_file": patch_path.relative_to(patch_plan_report.parent).as_posix(),
                "plan": child_plan,
            }
        )
        patch_outputs.append((patch_path, child_patch))
        model_results.append({"project": target.get("project"), "result": model_result})

    model_statuses = [str(item["result"].get("status") or "failed") for item in model_results]
    plan_statuses = [str(item["plan"].get("status") or "invalid") for item in repairs]
    model_analysis: dict[str, Any] = {
        "schema": "upc2030-agent-multi-repo-analysis-v1",
        "status": "success" if all(status == "success" for status in model_statuses) else "failed",
        "required": any(item["result"].get("required", True) for item in model_results),
        "analyses": model_results,
        "errors": [
            error
            for item in model_results
            for error in (item["result"].get("errors") or [])
        ],
    }
    if "invalid" in plan_statuses:
        aggregate_status = "invalid"
    elif "proposed" in plan_statuses:
        aggregate_status = "proposed"
    elif "insufficient_context" in plan_statuses:
        aggregate_status = "insufficient_context"
    elif "unavailable" in plan_statuses:
        aggregate_status = "unavailable"
    else:
        aggregate_status = "not_applicable"
    change_set = (report.get("repository_context") or {}).get("change_set") or {}
    patch_plan: dict[str, Any] = {
        "schema": REPAIR_PLAN_SCHEMA,
        "status": aggregate_status,
        "change_set_id": change_set.get("change_set_id"),
        "summary": f"Analyzed {len(repairs)} repositories from the active Change Set.",
        "repairs": repairs,
        "errors": [
            error
            for item in repairs
            for error in (item["plan"].get("errors") or [])
        ],
    }
    report["model_analysis"] = model_analysis
    report["model_analyses"] = model_results
    report["patch_plan"] = patch_plan
    if model_analysis["status"] == "success":
        report["engine"] = f"{ENGINE}+claude_agent_sdk"
    elif require_model and model_analysis.get("required", True):
        report["status"] = "failed"
        report["errors"].extend(model_analysis["errors"] or ["One or more model analyses failed"])
    if require_model and aggregate_status == "invalid":
        report["status"] = "failed"
        report["errors"].extend(patch_plan["errors"] or ["One or more repair plans are invalid"])

    try:
        write_json_atomic(json_report, report)
        write_text_atomic(markdown_report, render_markdown(report))
        write_json_atomic(patch_plan_report, patch_plan)
        # The aggregate workflow consumes per-repository patches. Keep the legacy
        # path empty so an older single-repository publisher cannot apply it.
        write_text_atomic(suggested_patch_report, "")
        for patch_path, patch_text in patch_outputs:
            write_text_atomic(patch_path, patch_text)
    except OSError as exc:
        print(f"[analyze_pipeline.py] ERROR: cannot write report: {exc}", file=sys.stderr)
        return 1

    print(f"[analyze_pipeline.py] {report['summary']}")
    print(f"[analyze_pipeline.py] Multi-repository patch plan: {patch_plan_report}")
    model_failed = (
        require_model
        and model_analysis.get("required", True)
        and model_analysis["status"] != "success"
    )
    patch_failed = require_model and aggregate_status == "invalid"
    return 1 if model_failed or patch_failed else 0


def analyze_pipeline(
    output_root: Path,
    json_report: Path,
    markdown_report: Path,
    *,
    patch_plan_report: Path | None = None,
    suggested_patch_report: Path | None = None,
    agent_config: Path | None = None,
    require_model: bool = False,
    environ: Mapping[str, str] | None = None,
    model_runner: Callable[..., dict[str, Any]] | None = None,
) -> int:
    """分析可用报告与日志；发现上游失败不会让分析 Job 自身失败。"""
    started_at = utc_now()
    findings: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    reports, pipeline_status = analyze_reports(output_root, findings, seen)
    logs = analyze_logs(output_root, findings, seen)
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F{index:03d}"

    counts = {
        "error": sum(item["severity"] == "error" for item in findings),
        "warning": sum(item["severity"] == "warning" for item in findings),
        "info": sum(item["severity"] == "info" for item in findings),
    }
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "completed",
        "finalized": True,
        "started_at": started_at,
        "finished_at": utc_now(),
        "engine": ENGINE,
        "repository_write_scope": "isolated_local_agent_branch_only",
        "pipeline_status": pipeline_status,
        "summary": summary_text(pipeline_status, findings),
        "finding_counts": counts,
        "findings": findings,
        "inputs": {"reports": reports, "logs": logs},
        "ci": ci_metadata(environ),
        "repository_context": repository_context(output_root, environ),
        "limitations": [
            "确定性规则始终运行；Claude 模型是否调用由配置和 ENABLE_AGENT_MODEL 决定。",
            "模型可读取全部同步源码，并仅在触发组件的本地 Agent 分支中 Edit 既有固件源码。",
            "模型不能运行命令或 Git；真实工作区差异会经过路径、准确 SHA 和 git apply --check 多层校验。",
            "提交、推送和 Draft MR 由独立发布 Job 完成，禁止自动合并。",
            "根因结论基于本次报告、日志和受控访问的同步源码。",
        ],
        "errors": [],
    }
    patch_plan_report = patch_plan_report or json_report.parent / "patch_plan.json"
    suggested_patch_report = suggested_patch_report or json_report.parent / "suggested.patch"
    context_projects = (report.get("repository_context") or {}).get("projects") or []
    repair_targets = [
        item
        for item in context_projects
        if isinstance(item, dict) and item.get("is_changeset_project") and item.get("ok")
    ]
    if len(repair_targets) > 1:
        return _analyze_multi_repo_changeset(
            report,
            repair_targets,
            json_report,
            markdown_report,
            patch_plan_report,
            suggested_patch_report,
            agent_config=agent_config,
            require_model=require_model,
            environ=environ,
            model_runner=model_runner,
        )

    report["model_analysis"] = analyze_with_claude(
        report,
        agent_config,
        environ=environ,
        runner=model_runner,
        cwd=Path.cwd(),
    )
    if report["model_analysis"]["status"] == "success":
        report["engine"] = f"{ENGINE}+claude_agent_sdk"
    elif require_model and report["model_analysis"].get("required", True):
        report["status"] = "failed"
        report["errors"].extend(report["model_analysis"].get("errors") or ["Claude 模型未执行成功"])
    patch_plan, suggested_patch = build_patch_artifacts(
        report,
        report["model_analysis"],
        workspace_root=Path.cwd(),
    )
    report["patch_plan"] = patch_plan
    if require_model and patch_plan["status"] == "invalid":
        report["status"] = "failed"
        report["errors"].extend(patch_plan["errors"] or ["Agent 补丁建议未通过安全校验"])
    try:
        write_json_atomic(json_report, report)
        write_text_atomic(markdown_report, render_markdown(report))
        write_json_atomic(patch_plan_report, patch_plan)
        write_text_atomic(suggested_patch_report, suggested_patch)
    except OSError as exc:
        print(f"[analyze_pipeline.py] ERROR: cannot write report: {exc}", file=sys.stderr)
        return 1
    print(f"[analyze_pipeline.py] {report['summary']}")
    print(f"[analyze_pipeline.py] JSON: {json_report}")
    print(f"[analyze_pipeline.py] Markdown: {markdown_report}")
    print(f"[analyze_pipeline.py] Patch plan: {patch_plan_report}")
    print(f"[analyze_pipeline.py] Suggested patch: {suggested_patch_report}")
    model_failed = (
        require_model
        and report["model_analysis"].get("required", True)
        and report["model_analysis"]["status"] != "success"
    )
    patch_failed = require_model and patch_plan["status"] == "invalid"
    return 1 if model_failed or patch_failed else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="生成 UPC2030 流水线 Agent 分析与修复报告")
    parser.add_argument("--output-root", type=Path, default=Path("ci_out"))
    parser.add_argument(
        "--json-report",
        type=Path,
        default=Path("ci_out/agent/agent_analysis.json"),
    )
    parser.add_argument(
        "--markdown-report",
        type=Path,
        default=Path("ci_out/agent/agent_analysis.md"),
    )
    parser.add_argument(
        "--patch-plan-report",
        type=Path,
        default=Path("ci_out/agent/patch_plan.json"),
    )
    parser.add_argument(
        "--suggested-patch-report",
        type=Path,
        default=Path("ci_out/agent/suggested.patch"),
    )
    parser.add_argument(
        "--agent-config",
        type=Path,
        default=None,
        help="Claude Agent 本地 YAML；CI 环境变量可覆盖其中的 provider 配置",
    )
    parser.add_argument(
        "--require-model",
        action="store_true",
        help="模型未成功返回结构化分析时令 Agent Job 失败",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return analyze_pipeline(
        args.output_root,
        args.json_report,
        args.markdown_report,
        patch_plan_report=args.patch_plan_report,
        suggested_patch_report=args.suggested_patch_report,
        agent_config=args.agent_config,
        require_model=args.require_model,
    )


if __name__ == "__main__":
    sys.exit(main())
