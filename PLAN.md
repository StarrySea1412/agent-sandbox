# VOL.17《把危险关进笼子》agent-sandbox

- 标本: hermes-agent-workbench/backend 的执行边界三件套（作者 starry-sea-1412）
  python_sandbox.py 217 行 + windows_job.py 71 行 + workspace_files.py 183 行，tests_python_sandbox.py 17 个测试
- 主题: 浅色警戒条纹（从 VOL.16 暗色座舱程序化换皮，变量名不动）
- 深度配方: 一次「代码进笼」全程走查（同一段代码过六道门：长度→import→进程→内存→时间→产物）
- 系列衔接: VOL.15 工具是手 → VOL.16 驾驶舱是眼 → VOL.17 笼子是手脚的权限

## 章节 ↔ 互动 ↔ 证据
01 笼子的哲学（诚实声明）| 互动01 威胁模型对照台 | 两处 docstring 原话 "not filesystem or network isolation"、META notes
02 五条硬上限（分层拒绝）| 互动02 分层闸门 | 8000/20/60/6000/2MB/512MB；test_code_size_limit、test_output_is_bounded_while_draining、600MB→MemoryError
03 import 闸门（正则真算）| 互动03 import 判定器 | BLOCKED_MODULES 12 个、BLOCKED_RE 定界符 trick、注释里的 import 也拦（宁可错杀）
04 内核围栏（Job Object）| 互动04 进程树围栏 | LimitFlags 0x2000|0x0200、JobMemoryLimit、attach 先于代码送达、test_job_setup_failure_does_not_run_code、test_closing_job_terminates_descendant
05 无形之门（环境/stdin）| 互动05 环境泄漏对照 | env 白名单 5 键、test_parent_secrets_are_not_inherited、-I 隔离模式、代码走 stdin
06 产物回传与清场 | 互动06 产物回传流水线 | ARTIFACT_SUFFIXES 4 种、2MB、手写 PNG 测试、tool_loop「预览直接给 stdout」、finally rmtree、registry 受控绑定

## 图
FIG.A hero SVG（笼子切面：六道门+代码走向）FIG.B hero GIF；ch1-ch6 各一张 WebP（C..H）
STYLE 后缀: 浅灰混凝土纸底色，钢青蓝描线主色，琥珀黄点缀，手绘工程插画，粗描线扁平化，无文字数字标识，轻工业车间质感
