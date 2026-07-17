// themes/manifest.js — 主题唯一清单（构建脚本与文档共用）
// 前端 HTML 内联代码由 build-themes.mjs 注入 generated 片段

export const DEFAULT_THEME_ID = "prairie";

export const THEME_ALIAS = {
  matrix: "prairie",
  aurora: "glass",
  ice: "paper",
  ember: "noir",
  "草原绿": "prairie",
  "默认": "default",
};

export const THEMES = [
  { id: "prairie", name: "原谅色", desc: "柔雾浅绿，清新治愈", file: "tokens/prairie.css", overrides: "overrides/prairie.css" },
  { id: "default", name: "极夜蓝", desc: "深蓝控制台", file: "tokens/default.css" },
  { id: "cyber", name: "书卷", desc: "旧书皮淡黄 · 羊皮纸", file: "tokens/cyber.css", overrides: "overrides/cyber.css" },
  { id: "noir", name: "墨夜", desc: "流行暗色 · 锌灰靛蓝", file: "tokens/noir.css", overrides: "overrides/noir.css" },
  { id: "glass", name: "琉璃", desc: "深空毛玻璃", file: "tokens/glass.css", overrides: "overrides/glass.css" },
  { id: "paper", name: "淡雅紫", desc: "淡紫雾感浅色", file: "tokens/paper.css", overrides: "overrides/paper.css" },
  { id: "crimson", name: "绛夜", desc: "深酒红 + 玫红琥珀", file: "tokens/crimson.css", overrides: "overrides/crimson.css" },
];
