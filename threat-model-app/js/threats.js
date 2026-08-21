// 威胁库数据：与 threat-model-checklist/webapp-threat-checklist.md 保持同步
// 字段：id 编号 / cat 元素类别 / title 名称 / stride STRIDE 分类 / sev 严重度 / ref OWASP 映射 / desc 攻击场景 / mitig 缓解措施
const THREAT_LIBRARY = [
  {
    "id": "G-01",
    "cat": "global",
    "title": "敏感数据未识别与分类",
    "stride": "Generic",
    "sev": "High",
    "ref": "A02:2021 / V1.8 / CS: User Privacy",
    "desc": "元素处理的数据含个人身份、金融、健康、凭证等信息但未分类分级，保护措施缺位。",
    "mitig": "建立数据分类清单，明确每个元素上数据的机密性/完整性/可用性要求；敏感数据全程标记。"
  },
  {
    "id": "G-02",
    "cat": "global",
    "title": "日志与监控盲区",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "A09:2021 / V7.x / CS: Logging",
    "desc": "关键安全事件（认证、授权变更、管理操作、异常输入）无日志，攻击无法溯源。",
    "mitig": "定义必须记录的安全事件清单；集中式日志；对日志访问做访问控制。"
  },
  {
    "id": "G-03",
    "cat": "global",
    "title": "密钥与凭据管理失控",
    "stride": "Generic",
    "sev": "High",
    "ref": "A02/A07:2021 / V6.x / CS: Secrets Management",
    "desc": "API Key、口令、签名密钥硬编码在代码、配置或环境变量中长期不轮换。",
    "mitig": "使用 KMS/Vault；按环境隔离；定期轮换；禁止明文入库入仓。"
  },
  {
    "id": "G-04",
    "cat": "global",
    "title": "依赖与供应链风险",
    "stride": "Generic",
    "sev": "High",
    "ref": "A06:2021 / CS: Supply Chain Security",
    "desc": "开源组件/基础镜像/前端包被投毒或存在已知漏洞。",
    "mitig": "SBOM 清单、SCA 扫描、版本锁定、私有镜像仓库、CI 阻断高危依赖。"
  },
  {
    "id": "G-05",
    "cat": "global",
    "title": "安全配置基线缺失",
    "stride": "Generic",
    "sev": "High",
    "ref": "A05:2021 / V14.x / CS: HTTP Headers",
    "desc": "默认配置上线：默认口令、调试模式、多余端口、目录列表。",
    "mitig": "按 CIS 基线加固；配置即代码并评审；上线前配置核查。"
  },
  {
    "id": "EE-S01",
    "cat": "actor",
    "title": "凭证暴力破解与撞库",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / WSTG-ATHN-002",
    "desc": "攻击者对登录接口批量尝试弱口令或泄露口令库，冒充合法用户。",
    "mitig": "锁定与指数退避；Argon2/bcrypt 存储；人机校验；异地设备告警；MFA。"
  },
  {
    "id": "EE-S02",
    "cat": "actor",
    "title": "会话劫持与会话固定",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / WSTG-SESS-001",
    "desc": "窃取 Cookie/Token 或强制使用已知会话 ID 完成仿冒。",
    "mitig": "Cookie HttpOnly/Secure/SameSite；登录提权后轮换会话 ID；短时效与空闲超时。"
  },
  {
    "id": "EE-S03",
    "cat": "actor",
    "title": "钓鱼与社会工程",
    "stride": "Spoofing",
    "sev": "Medium",
    "ref": "A07:2021 / CS: Multifactor Authentication",
    "desc": "仿冒站点或客服诱导用户交出凭证或 MFA 验证码。",
    "mitig": "抗钓鱼 MFA（FIDO2/Passkey）；仿冒站点监控下线流程；用户教育。"
  },
  {
    "id": "EE-T01",
    "cat": "actor",
    "title": "XSS 在用户浏览器执行脚本",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.3 / WSTG-INPV-001",
    "desc": "用户可控内容未编码进入页面，攻击脚本在受害者浏览器执行。",
    "mitig": "输出按上下文编码；禁用 v-html/innerHTML；严格 CSP(nonce)；富文本白名单。"
  },
  {
    "id": "EE-T02",
    "cat": "actor",
    "title": "CSRF 冒用身份执行状态变更",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A01:2021 / V3.4 / WSTG-SESS-005",
    "desc": "第三方页面诱导浏览器向转账、改密等接口发请求。",
    "mitig": "SameSite Cookie；CSRF Token；敏感操作二次验证；不用 GET 变更状态。"
  },
  {
    "id": "EE-R01",
    "cat": "actor",
    "title": "用户否认操作且无审计",
    "stride": "Repudiation",
    "sev": "Medium",
    "ref": "A09:2021 / V7.1",
    "desc": "用户否认下单/转账/删除等操作，缺少绑定身份的证据链。",
    "mitig": "关键操作记录 who/what/when/where/IP；时间戳可信；留存操作流水。"
  },
  {
    "id": "EE-E01",
    "cat": "actor",
    "title": "用户身份被用于水平越权",
    "stride": "ElevationOfPrivilege",
    "sev": "High",
    "ref": "A01:2021 / V4.2 / WSTG-ATHZ-002",
    "desc": "以普通用户身份遍历对象 ID（订单号、文件 ID）访问他人数据。",
    "mitig": "服务端每次访问做属主校验（默认拒绝）；不可枚举 ID；对象级授权测试入 CI。"
  },
  {
    "id": "EE-S04",
    "cat": "actor",
    "title": "管理员账号被入侵",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V2.8",
    "desc": "管理员凭证泄露或被钓鱼，攻击者获得最高权限入口。",
    "mitig": "强制 MFA；跳板机/零信任接入；最小权限拆分角色；特权会话录制。"
  },
  {
    "id": "EE-E02",
    "cat": "actor",
    "title": "管理员权限滥用",
    "stride": "ElevationOfPrivilege",
    "sev": "High",
    "ref": "A01:2021 / V1.4",
    "desc": "合法管理员越权查看/修改非职责范围数据。",
    "mitig": "职责分离；高风险操作双人复核；管理操作全量审计告警；数据脱敏展示。"
  },
  {
    "id": "EE-S05",
    "cat": "actor",
    "title": "OAuth 回调伪造与授权码拦截",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V2.9 / CS: OAuth2",
    "desc": "伪造 redirect_uri 或拦截授权码/令牌，完成账号接管。",
    "mitig": "redirect_uri 精确白名单；state 防 CSRF；授权码一次性+PKCE；token 不经 URL。"
  },
  {
    "id": "EE-T03",
    "cat": "actor",
    "title": "第三方返回数据注入",
    "stride": "Tampering",
    "sev": "Medium",
    "ref": "A08/A03:2021 / V5.3",
    "desc": "第三方返回内容（姓名、Webhook payload）含恶意载荷进入渲染或解析链。",
    "mitig": "外部数据按用户输入同级校验编码；schema 校验；Webhook 签名验证。"
  },
  {
    "id": "EE-I01",
    "cat": "actor",
    "title": "向第三方过度共享数据",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A02:2021 / CS: User Privacy",
    "desc": "集成第三方时发送超出必要的用户数据，造成合规与泄露风险。",
    "mitig": "数据最小化；共享字段清单评审留档；签署 DPA；敏感字段脱敏后共享。"
  },
  {
    "id": "EE-D01",
    "cat": "actor",
    "title": "第三方服务不可用拖垮主流程",
    "stride": "DenialOfService",
    "sev": "Medium",
    "ref": "A04:2021 / CS: Denial of Service",
    "desc": "支付/短信/身份服务故障或限流，核心链路全部阻塞。",
    "mitig": "超时与重试上限；熔断降级与备用通道；关键第三方双供应商。"
  },
  {
    "id": "PR-S01",
    "cat": "process",
    "title": "服务身份伪造（服务间无认证）",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V2.6 / CS: Microservices",
    "desc": "内网任一主机可冒充下游服务调用接口，绕过前端所有控制。",
    "mitig": "服务间 mTLS 或网格身份；每服务独立凭证最小权限；零信任默认拒绝。"
  },
  {
    "id": "PR-S02",
    "cat": "process",
    "title": "令牌伪造与 JWT 算法混淆",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V3.5 / WSTG-SESS-010 / CS: JWT",
    "desc": "JWT 弱密钥、允许 alg none 或 RS/HS 混淆，攻击者自签管理员令牌。",
    "mitig": "算法白名单固定；强密钥入 KMS；完整校验 iss/aud/exp；短时效与撤销机制。"
  },
  {
    "id": "PR-T01",
    "cat": "process",
    "title": "SQL / NoSQL / LDAP 注入",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.3.4 / WSTG-INPV-005",
    "desc": "用户输入拼接进查询语句，读取/篡改整个数据库。",
    "mitig": "参数化查询与预编译；ORM 禁止拼接；输入白名单；最小权限账号兜底。"
  },
  {
    "id": "PR-T02",
    "cat": "process",
    "title": "操作系统命令注入",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.3.5 / WSTG-INPV-012",
    "desc": "文件名、URL、导出参数拼入 shell 命令执行任意命令。",
    "mitig": "避免调用 shell；参数化 API；输入白名单；沙箱容器运行。"
  },
  {
    "id": "PR-T03",
    "cat": "process",
    "title": "不安全反序列化",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A08:2021 / V5.5 / WSTG-INPV-011",
    "desc": "反序列化来自缓存/MQ/Cookie 的对象，构造 gadget 链实现 RCE。",
    "mitig": "不反序列化不可信数据；改用 JSON；必须时签名+类型白名单+低权限容器。"
  },
  {
    "id": "PR-T04",
    "cat": "process",
    "title": "SSRF 服务端请求伪造",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A10:2021 / V12.6.1 / WSTG-SSRF",
    "desc": "URL 预览、Webhook、图片拉取被诱导访问内网元数据服务或管理端口。",
    "mitig": "URL 白名单（协议+域名+端口）；禁用重定向；网络层阻断内网；IMDSv2。"
  },
  {
    "id": "PR-T05",
    "cat": "process",
    "title": "恶意文件上传",
    "stride": "Tampering",
    "sev": "High",
    "ref": "V12.5 / WSTG-BUSL-009 / CS: File Upload",
    "desc": "上传 Webshell、压缩炸弹、含脚本 SVG，获取执行或拖垮服务。",
    "mitig": "扩展名+MIME+魔数白名单；文件名随机化；存储与 Web 根隔离；病毒扫描。"
  },
  {
    "id": "PR-T06",
    "cat": "process",
    "title": "模板注入（SSTI）",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.2",
    "desc": "用户输入进入模板引擎渲染，执行任意代码或读取文件。",
    "mitig": "模板与数据严格分离；逻辑无关模板引擎；沙箱化渲染。"
  },
  {
    "id": "PR-I01",
    "cat": "process",
    "title": "详细错误与堆栈泄露",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A05:2021 / V7.4.1 / WSTG-ERRH-01",
    "desc": "异常页输出堆栈、SQL、框架版本，暴露攻击面情报。",
    "mitig": "全局异常处理器统一错误结构；细节只进日志；关闭调试模式。"
  },
  {
    "id": "PR-I02",
    "cat": "process",
    "title": "API 响应过度暴露数据",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "API1:2023 / A01:2021 / V4.3",
    "desc": "接口返回整表对象（含哈希、内部字段、他人数据），客户端只显示一部分。",
    "mitig": "响应 DTO 白名单字段；对象级授权；敏感字段服务端过滤。"
  },
  {
    "id": "PR-I03",
    "cat": "process",
    "title": "缓存投毒与 Web 缓存欺骗",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A05:2021 / CS: HTTP Headers",
    "desc": "非缓存键头被反射并缓存，或诱导缓存存住用户数据页面。",
    "mitig": "缓存键覆盖所有影响响应的头；不缓存带会话 Cookie 的响应；Cache-Control 正确。"
  },
  {
    "id": "PR-R01",
    "cat": "process",
    "title": "关键操作无审计日志",
    "stride": "Repudiation",
    "sev": "Medium",
    "ref": "A09:2021 / V7.2 / CS: Logging",
    "desc": "登录、提权、导出、删除等操作无日志，无法还原攻击链。",
    "mitig": "安全事件日志清单；日志含用户/IP/trace id；防篡改传输到中心。"
  },
  {
    "id": "PR-D01",
    "cat": "process",
    "title": "缺少速率限制的自动化滥用",
    "stride": "DenialOfService",
    "sev": "High",
    "ref": "A04:2021 / V11.1 / API4:2023",
    "desc": "注册、登录、短信、查询接口被脚本高频调用，撞库、刷量、耗尽资源。",
    "mitig": "按 IP/账号/设备多维限流；业务配额；人机校验；WAF bot 管理。"
  },
  {
    "id": "PR-D02",
    "cat": "process",
    "title": "应用层资源耗尽",
    "stride": "DenialOfService",
    "sev": "Medium",
    "ref": "A04:2021 / V12.x",
    "desc": "ReDoS、深度分页、超大 JSON、慢速攻击耗尽 CPU/内存/连接池。",
    "mitig": "正则安全审计；请求体/深度/分页上限；查询超时；反向代理超时配置。"
  },
  {
    "id": "PR-E01",
    "cat": "process",
    "title": "IDOR 水平越权（对象级）",
    "stride": "ElevationOfPrivilege",
    "sev": "High",
    "ref": "A01:2021 / V4.2 / WSTG-ATHZ-002",
    "desc": "接口只验证登录态未验证数据属主，遍历 ID 批量拉取他人数据。",
    "mitig": "每次访问做对象级授权判断；查询加属主条件；自动化越权测试。"
  },
  {
    "id": "PR-E02",
    "cat": "process",
    "title": "垂直越权与功能级授权缺失",
    "stride": "ElevationOfPrivilege",
    "sev": "High",
    "ref": "A01:2021 / V4.1 / WSTG-ATHZ-003",
    "desc": "普通用户直接请求管理接口成功；前端隐藏按钮但后端未校验角色。",
    "mitig": "后端默认拒绝+角色白名单；管理面独立入口二次认证；权限矩阵测试。"
  },
  {
    "id": "PR-E03",
    "cat": "process",
    "title": "Mass Assignment 批量赋值",
    "stride": "ElevationOfPrivilege",
    "sev": "Medium",
    "ref": "API3:2023 / V4.5.4",
    "desc": "请求体直接绑定实体，追加 role=admin 或 price=0 修改服务端字段。",
    "mitig": "入参 DTO 显式声明字段；禁用自动绑定敏感属性；PATCH 白名单。"
  },
  {
    "id": "PR-E04",
    "cat": "process",
    "title": "业务逻辑滥用",
    "stride": "ElevationOfPrivilege",
    "sev": "Medium",
    "ref": "A04:2021 / V11.7 / CS: Business Logic",
    "desc": "跳过支付直接发货、并发重复领券、负数数量下单、验证码重放。",
    "mitig": "状态机服务端校验；关键操作幂等+分布式锁；金额数量服务端计算；风控监测。"
  },
  {
    "id": "PR-T07",
    "cat": "process",
    "title": "第三方脚本供应链投毒",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A06/A08:2021 / CS: Third Party Javascript",
    "desc": "引入的统计/客服/广告 JS 被投毒或账号被盗，在所有用户页面执行恶意代码。",
    "mitig": "SRI 子资源完整性；CSP 限制脚本来源；关键脚本自托管；订阅安全通告。"
  },
  {
    "id": "PR-T08",
    "cat": "process",
    "title": "点击劫持与嵌入滥用",
    "stride": "Tampering",
    "sev": "Low",
    "ref": "A05:2021 / WSTG-CLNT-009",
    "desc": "站点被 iframe 嵌套叠加透明层，诱导用户点击转账/授权按钮。",
    "mitig": "X-Frame-Options: DENY 与 CSP frame-ancestors 'none'；敏感页禁止嵌入。"
  },
  {
    "id": "PR-I04",
    "cat": "process",
    "title": "前端源码与配置泄露",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A05:2021 / WSTG-INFO-005",
    "desc": "sourcemap、.git 目录、备份文件、硬编码测试凭证随静态资源发布。",
    "mitig": "构建产物扫描；生产禁用/限制 sourcemap；禁止敏感扩展名；CI 密钥扫描。"
  },
  {
    "id": "PR-S03",
    "cat": "process",
    "title": "弱口令策略与弱哈希存储",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V2.1/V2.4 / CS: Password Storage",
    "desc": "允许弱口令；MD5/SHA1 或可逆方式存储口令，拖库后秒破。",
    "mitig": "长度优先策略（>=12）；Argon2id/bcrypt 加盐；常用口令黑名单。"
  },
  {
    "id": "PR-S04",
    "cat": "process",
    "title": "用户枚举与找回流程滥用",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A07:2021 / V2.1.9 / WSTG-IDNT-004",
    "desc": "登录/注册/找回接口响应差异暴露账号存在性；找回链接可暴力枚举。",
    "mitig": "统一响应文案与时延；找回 token 高熵一次性短时效；验证码防枚举。"
  },
  {
    "id": "PR-T09",
    "cat": "process",
    "title": "认证绕过逻辑缺陷",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V2.x / WSTG-ATHN",
    "desc": "改绑手机/邮箱后旧凭证仍有效；验证码校验可跳过；OAuth 绑定可伪造。",
    "mitig": "关键状态变更后失效旧凭证；服务端完整校验状态机；绑定验证双方所有权。"
  },
  {
    "id": "PR-S05",
    "cat": "process",
    "title": "网关鉴权旁路",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A01/A07:2021 / API1:2023",
    "desc": "内部路由/调试端点绕过网关认证直达下游；旧版本 API 无鉴权。",
    "mitig": "网关默认拒绝全量路由清单；下游仅接受网关流量（mTLS）；版本下线机制。"
  },
  {
    "id": "PR-I05",
    "cat": "process",
    "title": "跨域与 API 元数据暴露",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A05:2021 / V14.5 / WSTG-CONF-007",
    "desc": "CORS 反射任意 Origin 且允许凭据；swagger/GraphQL 内省生产开放。",
    "mitig": "CORS 白名单精确到协议+域名；生产关闭文档与内省；GraphQL 复杂度限制。"
  },
  {
    "id": "PR-T10",
    "cat": "process",
    "title": "毒消息与恶意 payload",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A08:2021 / CS: Deserialization",
    "desc": "队列消息被伪造篡改，消费者反序列化 RCE 或循环崩溃。",
    "mitig": "消息签名校验；schema 校验后处理；毒消息进死信队列告警；最小权限运行。"
  },
  {
    "id": "PR-R02",
    "cat": "process",
    "title": "任务执行无审计且可被外部触发",
    "stride": "Repudiation",
    "sev": "Medium",
    "ref": "A09:2021 / V12.6",
    "desc": "管理任务接口暴露，任何人可触发重算/导出/发信，事后无日志。",
    "mitig": "任务触发鉴权+二次确认；任务参数与结果审计；导出脱敏并设有效期。"
  },
  {
    "id": "DS-I01",
    "cat": "store",
    "title": "敏感数据明文存储",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "A02:2021 / V6.2 / WSTG-CRYP-003 / CS: Cryptographic Storage",
    "desc": "口令、身份证、银行卡、Token 明文或弱加密落库，拖库即全部泄露。",
    "mitig": "口令只存 Argon2/bcrypt 哈希；敏感字段 AES-256-GCM，密钥在 KMS 与数据分离。"
  },
  {
    "id": "DS-I02",
    "cat": "store",
    "title": "备份与导出未加密未管控",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "A02:2021 / V8.3",
    "desc": "备份/Dump/导出文件未加密存放或随意下载，成为旁路泄露源。",
    "mitig": "备份加密+独立密钥；下载走审批与审计；保留与销毁策略。"
  },
  {
    "id": "DS-I03",
    "cat": "store",
    "title": "对象存储 ACL 错配公开可读",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "A05:2021 / V1.14 / CS: Secure Cloud Architecture",
    "desc": "Bucket/目录误设 public-read，身份证图片、报表被搜索引擎索引。",
    "mitig": "默认私有+阻止公共访问；预签名 URL 短时效最小权限；定期扫描公开资源。"
  },
  {
    "id": "DS-I04",
    "cat": "store",
    "title": "日志与消息队列中泄露敏感数据",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A09:2021 / V7.3.1 / CS: Logging",
    "desc": "日志打印完整请求体（口令、Token）、队列携带明文敏感字段。",
    "mitig": "结构化日志字段白名单；敏感字段打码/哈希；采集链路加密与访问控制。"
  },
  {
    "id": "DS-T01",
    "cat": "store",
    "title": "注入到达存储层篡改数据",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.3 / WSTG-INPV-005",
    "desc": "应用层注入或直接 DB 访问导致批量改写记录（改余额、改权限字段）。",
    "mitig": "最小权限账号无 DDL；关键字段完整性校验与审计列；变更审计触发器。"
  },
  {
    "id": "DS-T02",
    "cat": "store",
    "title": "缓存与消息数据被篡改",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A08:2021 / CS: Deserialization",
    "desc": "Redis/MQ 无认证或弱认证，攻击者改写缓存内容或注入伪造消息。",
    "mitig": "强认证+网络隔离；消息与关键缓存值签名；读取侧校验。"
  },
  {
    "id": "DS-R01",
    "cat": "store",
    "title": "审计数据可删改（无不可否认性）",
    "stride": "Repudiation",
    "sev": "Medium",
    "ref": "A09:2021 / V7.2 / CS: Logging",
    "desc": "审计日志与应用同库同账号，攻击者入库后直接删日志。",
    "mitig": "日志追加写（WORM）；集中 SIEM 实时外发；日志账号与应用分离不可删。"
  },
  {
    "id": "DS-E01",
    "cat": "store",
    "title": "数据库账号过度授权",
    "stride": "ElevationOfPrivilege",
    "sev": "High",
    "ref": "A05:2021 / V4.9 / CS: Database Security",
    "desc": "应用使用 root/sa 连接，注入后可读任意库、执行系统命令、建后门。",
    "mitig": "按应用拆分最小权限账号；禁用 FILE/ADMIN 权限；应用账号禁止 DDL。"
  },
  {
    "id": "DS-D01",
    "cat": "store",
    "title": "存储层资源耗尽",
    "stride": "DenialOfService",
    "sev": "Medium",
    "ref": "A04:2021 / V12.x",
    "desc": "大查询、连接占满、磁盘写爆导致整体不可用。",
    "mitig": "查询超时与最大返回行数；连接池上限；磁盘水位告警与清理策略。"
  },
  {
    "id": "DS-S01",
    "cat": "store",
    "title": "缓存未授权访问",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "A05:2021 / V1.14 / CS: Database Security",
    "desc": "Redis/Memcached 暴露且弱口令，读取会话数据或 EVAL 执行命令。",
    "mitig": "仅内网监听+强口令；TLS 与 ACL；安全组白名单；配置扫描。"
  },
  {
    "id": "DS-D02",
    "cat": "store",
    "title": "缓存穿透/击穿/雪崩放大故障",
    "stride": "DenialOfService",
    "sev": "Medium",
    "ref": "A04:2021 / CS: Denial of Service",
    "desc": "不存在 key 或同时过期导致请求全部打到数据库，连锁雪崩。",
    "mitig": "空值缓存与布隆过滤器；热点 key 逻辑过期；TTL 随机抖动；熔断限流。"
  },
  {
    "id": "DF-I01",
    "cat": "flow",
    "title": "明文传输与弱 TLS 配置",
    "stride": "InformationDisclosure",
    "sev": "High",
    "ref": "A02:2021 / V9.1 / WSTG-CRYP-001 / CS: Transport Layer Security",
    "desc": "HTTP 明文、TLS 1.0/1.1、弱密码套件或证书校验关闭，流量被窃听篡改。",
    "mitig": "全站强制 TLS 1.2+ 与现代套件；HSTS preload；内部服务间同样 TLS/mTLS。"
  },
  {
    "id": "DF-S01",
    "cat": "flow",
    "title": "中间人（MITM）与证书伪造",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A02/A07:2021 / V9.1 / CS: Pinning",
    "desc": "公共网络下劫持 DNS 或自签证书冒充服务端截获凭证。",
    "mitig": "HSTS 防降级；关键客户端证书固定；服务间 mTLS；证书透明度监控。"
  },
  {
    "id": "DF-I02",
    "cat": "flow",
    "title": "敏感数据出现在 URL 中",
    "stride": "InformationDisclosure",
    "sev": "Medium",
    "ref": "A02:2021 / V3.5.1",
    "desc": "token、手机号放查询串，被浏览器历史、Referer、代理与日志留存。",
    "mitig": "凭证只走 Header/Body/Cookie；敏感参数 POST；Referer-Policy 与日志脱敏。"
  },
  {
    "id": "DF-T01",
    "cat": "flow",
    "title": "请求重放与消息重放",
    "stride": "Tampering",
    "sev": "Medium",
    "ref": "A08:2021 / V13.3.2 / CS: REST Security",
    "desc": "抓包重放支付/下单/验证码请求，造成重复扣款或短信轰炸。",
    "mitig": "幂等键；nonce+时间戳窗口；一次性 token；Webhook 去重。"
  },
  {
    "id": "DF-S02",
    "cat": "flow",
    "title": "凭证随流量分发泄露",
    "stride": "Spoofing",
    "sev": "High",
    "ref": "A07:2021 / V6.2 / CS: Secrets Management",
    "desc": "数据库口令、云 AK/SK 硬编码在客户端代码、镜像层或配置明文传递。",
    "mitig": "密钥只存在 KMS/Secret 存储；短期凭证替代静态 AK/SK；制品扫描密钥。"
  },
  {
    "id": "DF-T02",
    "cat": "flow",
    "title": "跨边界数据未校验即信任",
    "stride": "Tampering",
    "sev": "High",
    "ref": "A03:2021 / V5.1 / CS: Input Validation",
    "desc": "来自前端/第三方/消息队列的数据被默认信任，跳过校验直接入库或执行。",
    "mitig": "跨边界输入做 schema+白名单校验（信任但验证）；统一校验层；异常输入拒绝并告警。"
  },
  {
    "id": "TB-Q01",
    "cat": "boundary",
    "title": "认证：穿越边界的流是否完成调用方身份认证",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "每条穿越信任边界的 Flow，调用方是否经过认证（用户会话/服务 mTLS/任务身份）。",
    "mitig": "未认证的跨边界流补齐认证机制后再放行。"
  },
  {
    "id": "TB-Q02",
    "cat": "boundary",
    "title": "授权：边界内是否默认拒绝的对象级+功能级授权",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "边界内服务是否对每个请求做默认拒绝的授权判断。",
    "mitig": "补齐服务端授权检查，覆盖对象级与功能级。"
  },
  {
    "id": "TB-Q03",
    "cat": "boundary",
    "title": "输入校验：跨边界数据是否先校验后处理",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "跨边界数据是否在做 schema 与白名单校验后才进入内部处理。",
    "mitig": "在边界处建立统一校验层。"
  },
  {
    "id": "TB-Q04",
    "cat": "boundary",
    "title": "加密终结点：TLS 终结后到下游是否仍有保护",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "TLS 在哪里终结？终结点之后的内网段是否有保护措施。",
    "mitig": "敏感流量端到端加密或在内网继续 TLS/mTLS。"
  },
  {
    "id": "TB-Q05",
    "cat": "boundary",
    "title": "暴露面最小化：管理端口与调试端点是否只在可信侧",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "管理端口、调试端点、健康检查、metrics 是否暴露在不可信侧。",
    "mitig": "管理面与调试端点仅内网/白名单可达。"
  },
  {
    "id": "TB-Q06",
    "cat": "boundary",
    "title": "跨边界审计：进入高权限区操作是否全部留痕",
    "stride": "Generic",
    "sev": "Medium",
    "ref": "TB 审查问题",
    "desc": "进入高权限区的操作是否全部记录并告警。",
    "mitig": "跨边界关键操作全量审计并接入告警。"
  }
];
