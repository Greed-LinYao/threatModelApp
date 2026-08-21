# 威胁建模工作台

纯前端单页应用:多项目 / 页面 / 功能 / 威胁勾选(69 条 Web 威胁库) / 数据流与上下游关系 / 关系图视图 / 导出 JSON 与百度脑图 .km。无后端、无构建步骤、无外部依赖,数据自动保存于浏览器 localStorage。

## 目录结构

```
threat-model-app/
├── index.html       # 应用页面与样式
└── js/
    ├── threats.js   # 威胁库数据(69 条,基于 OWASP Top 10/ASVS/WSTG)
    └── app.js       # 全部业务逻辑
```

## 快速启动(任选其一)

### 方式一:任意静态文件服务器

```bash
# 进入应用目录
cd threat-model-app

# Python(通常系统自带)
python3 -m http.server 8080

# 或 Node.js
npx serve -l 8080 .
```

浏览器打开 http://localhost:8080 即可。

### 方式二:Nginx

```nginx
server {
    listen 8080;
    server_name _;
    root /opt/threat-model-app;   # 指向应用目录
    index index.html;
}
```

### 方式三:直接双击打开

直接用浏览器打开 index.html 也能用(file:// 协议),所有功能均可用,不依赖任何网络请求。

## 使用流程

1. 首次进入点右上角"示例项目"载入云上商城示例,体验完整流程
2. "新建项目"可创建多个并存项目,左上角下拉框切换,项目间可建立跨项目数据流/上下游
3. 每个项目下建页面 -> 页面下建功能 -> 功能上勾选威胁(支持按类别/STRIDE/严重度/关键词筛选)
4. 威胁条目点击可循环切换状态:未处理 -> 已缓解 -> 不适用
5. 顶部"关系图"标签页可视化查看本页面与外部/跨项目功能的连线关系
6. 数据自动保存(localStorage);"导出项目/导出全部"生成 JSON 备份,可随时导入恢复

## 导出格式

- **JSON**:单个项目或全部项目,含 `format: "threat-model-workbench"` 标识,可回导
- **.km**:百度脑图格式(https://naotu.baidu.com 或百度脑图客户端打开),威胁严重度映射为优先级图标,威胁状态映射为资源标签

## 数据存储说明

- 所有数据保存在浏览器 localStorage(key: `tm-workbench-v2`)
- 换浏览器/清缓存前请先"导出全部"做备份
- 旧版 v1 数据首次打开时自动迁移

## 威胁库来源

69 条威胁项按 DFD 元素分类(外部实体/过程/数据存储/数据流/信任边界/全局),覆盖 STRIDE 六类,基于 OWASP Top 10 (2021)、OWASP ASVS 4.0.3、OWASP WSTG v4.2、OWASP API Security Top 10 (2023) 整理。
