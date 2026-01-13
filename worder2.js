import { connect } from 'cloudflare:sockets';

// ==================== 配置管理 ====================
const Config = {
    // 协议常量
    PROTOCOL: 'vless',
    EXPIRE: 4102329600,
    HTTP_PORTS: ["8080", "8880", "2052", "2082", "2086", "2095"],
    HTTPS_PORTS: ["2053", "2083", "2087", "2096", "8443"],
    WS_READY_STATE_OPEN: 1,
    WS_READY_STATE_CLOSING: 2,
    
    // 默认值
    defaults: {
        subConverter: atob('U3ViQXBpLkNtbGlVc3NzUy5OZXQ='),
        subConfig: atob('aHR0cHM6Ly9yYXcuZ2l0aHViYXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ=='),
        fileName: atob('ZWRnZXR1bm5lbA=='),
        banHosts: [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')],
        go2Socks5s: ['*ttvnw.net', '*tapecontent.net', '*.cloudatacdn.com', '*.loadshare.org'],
    },
    
    // 运行时配置
    runtime: {
        userID: '',
        userIDLow: '',
        proxyIP: '',
        socks5Address: '',
        parsedSocks5: null,
        enableSocks: false,
        enableHttp: false,
        proxyIPs: [],
        socks5s: [],
        go2Socks5s: [],
        addresses: [],
        addressesapi: [],
        addressesnotls: [],
        addressesnotlsapi: [],
        addressescsv: [],
        proxyIPPool: [],
        banHosts: [],
        DNS64Server: '',
        path: '/?ed=2560',
        dynamicUUID: '',
        requestProxyIP: 'false',
        subProtocol: 'https',
        subEmoji: 'true',
        subConverter: '',
        subConfig: '',
        DLS: 8,
        remarkIndex: 1,
        fileName: '',
        botToken: '',
        chatID: '',
        link: [],
        proxyhosts: [],
        proxyhostsURL: atob('aHR0cHM6Ly9yYXcuZ2l0aHViYXNlcmNvbnRlbnQuY29tL2NtbGl1L2NtbGl1L21haW4vUHJveHlIT1NU'),
        noTLS: 'false',
        SCV: 'true',
        allowInsecure: '&allowInsecure=1',
        effectiveTime: 7,
        updateTime: 3,
    },
    
    // 从环境变量加载配置
    init(env) {
        this.runtime.userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || '';
        this.runtime.proxyIP = env.PROXYIP || env.proxyip || '';
        this.runtime.DNS64Server = env.DNS64 || env.NAT64 || '';
        this.runtime.socks5Address = env.HTTP || env.SOCKS5 || '';
        this.runtime.subConverter = env.SUBAPI || this.defaults.subConverter;
        this.runtime.subConfig = env.SUBCONFIG || this.defaults.subConfig;
        this.runtime.fileName = env.SUBNAME || this.defaults.fileName;
        this.runtime.botToken = env.TGTOKEN || '';
        this.runtime.chatID = env.TGID || '';
        this.runtime.DLS = Number(env.DLS) || this.runtime.DLS;
        this.runtime.remarkIndex = Number(env.CSVREMARK) || this.runtime.remarkIndex;
        this.runtime.subEmoji = env.SUBEMOJI || env.EMOJI || this.runtime.subEmoji;
        if (this.runtime.subEmoji == '0') this.runtime.subEmoji = 'false';
        this.runtime.SCV = env.SCV || this.runtime.SCV;
        if (!this.runtime.SCV || this.runtime.SCV == '0' || this.runtime.SCV == 'false') {
            this.runtime.allowInsecure = '';
        } else {
            this.runtime.SCV = 'true';
        }
        this.runtime.effectiveTime = Number(env.TIME) || this.runtime.effectiveTime;
        this.runtime.updateTime = Number(env.UPTIME) || this.runtime.updateTime;
        
        // 处理子转换器协议
        if (this.runtime.subConverter.includes("http://")) {
            this.runtime.subConverter = this.runtime.subConverter.split("//")[1];
            this.runtime.subProtocol = 'http';
        } else {
            this.runtime.subConverter = this.runtime.subConverter.split("//")[1] || this.runtime.subConverter;
        }
        
        return this.runtime;
    },
    
    // 加载列表数据
    async loadLists(env) {
        const lists = ['PROXYIP', 'GO2SOCKS5', 'CFPORTS', 'BAN', 'ADD', 'ADDAPI', 'ADDNOTLS', 'ADDNOTLSAPI', 'ADDCSV', 'LINK'];
        const mappings = {
            PROXYIP: 'proxyIPs',
            GO2SOCKS5: 'go2Socks5s',
            CFPORTS: 'httpsPorts',
            BAN: 'banHosts',
            ADD: 'addresses',
            ADDAPI: 'addressesapi',
            ADDNOTLS: 'addressesnotls',
            ADDNOTLSAPI: 'addressesnotlsapi',
            ADDCSV: 'addressescsv',
            LINK: 'link'
        };
        
        for (const key of lists) {
            if (env[key]) {
                const parsed = await Utils.organizeContent(env[key]);
                const targetKey = mappings[key];
                if (targetKey && this.runtime[targetKey] !== undefined) {
                    this.runtime[targetKey] = parsed;
                }
            }
        }
    }
};

// ==================== 工具函数 ====================
const Utils = {
    // 整理字符串为数组
    async organizeContent(content) {
        if (!content) return [];
        let processedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
        if (processedContent.charAt(0) == ',') processedContent = processedContent.slice(1);
        if (processedContent.charAt(processedContent.length - 1) == ',') processedContent = processedContent.slice(0, processedContent.length - 1);
        return processedContent.split(',');
    },
    
    // UUID验证
    isValidUUID(uuid) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
    },
    
    // 双重哈希
    async doubleHash(text) {
        const encoder = new TextEncoder();
        const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
        const firstHashArray = Array.from(new Uint8Array(firstHash));
        const firstHashHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        
        const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHashHex.slice(7, 27)));
        const secondHashArray = Array.from(new Uint8Array(secondHash));
        const secondHashHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        
        return secondHashHex.toLowerCase();
    },
    
    // Base64转ArrayBuffer
    base64ToArrayBuffer(base64Str) {
        if (!base64Str) return { earlyData: undefined, error: null };
        try {
            base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
            const decode = atob(base64Str);
            const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
            return { earlyData: arryBuffer.buffer, error: null };
        } catch (error) {
            return { earlyData: undefined, error };
        }
    },
    
    // IPv4验证
    isValidIPv4(address) {
        return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address);
    },
    
    // 生成动态UUID
    async generateDynamicUUID(key) {
        const timezoneOffset = 8;
        const startDate = new Date(2007, 6, 7, Config.runtime.updateTime, 0, 0);
        const weekMilliseconds = 1000 * 60 * 60 * 24 * Config.runtime.effectiveTime;
        
        function getCurrentWeekNumber() {
            const now = new Date();
            const adjustedNow = new Date(now.getTime() + timezoneOffset * 60 * 60 * 1000);
            const timeDiff = Number(adjustedNow) - Number(startDate);
            return Math.ceil(timeDiff / weekMilliseconds);
        }
        
        function generateUUID(baseString) {
            const hashBuffer = new TextEncoder().encode(baseString);
            return crypto.subtle.digest('SHA-256', hashBuffer).then((hash) => {
                const hashArray = Array.from(new Uint8Array(hash));
                const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                return `${hexHash.substr(0, 8)}-${hexHash.substr(8, 4)}-4${hexHash.substr(13, 3)}-${(parseInt(hexHash.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${hexHash.substr(18, 2)}-${hexHash.substr(20, 12)}`;
            });
        }
        
        const currentWeekNumber = getCurrentWeekNumber();
        const endTime = new Date(startDate.getTime() + currentWeekNumber * weekMilliseconds);
        const currentUUIDPromise = generateUUID(key + currentWeekNumber);
        const previousUUIDPromise = generateUUID(key + (currentWeekNumber - 1));
        const expirationTimeUTC = new Date(endTime.getTime() - timezoneOffset * 60 * 60 * 1000);
        const expirationTimeString = `Expiration Time (UTC): ${expirationTimeUTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${endTime.toISOString().slice(0, 19).replace('T', ' ')}\n`;
        
        return Promise.all([currentUUIDPromise, previousUUIDPromise, expirationTimeString]);
    },
    
    // SOCKS5地址解析
    socks5AddressParser(address) {
        const lastAtIndex = address.lastIndexOf("@");
        let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
        let username, password, hostname, port;
        
        if (former) {
            const formers = former.split(":");
            if (formers.length !== 2) throw new Error('无效的SOCKS地址格式');
            [username, password] = formers;
        }
        
        const latters = latter.split(":");
        if (latters.length > 2 && latter.includes("]:")) {
            port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
            hostname = latter.split("]:")[0] + "]";
        } else if (latters.length === 2) {
            port = Number(latters.pop().replace(/[^\d]/g, ''));
            hostname = latters.join(":");
        } else {
            port = 80;
            hostname = latter;
        }
        
        if (isNaN(port)) throw new Error('无效的端口号');
        if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) {
            throw new Error('IPv6地址必须用方括号括起来');
        }
        
        return { username, password, hostname, port };
    },
    
    // 安全关闭WebSocket
    safeCloseWebSocket(socket) {
        try {
            if (socket.readyState === Config.WS_READY_STATE_OPEN || socket.readyState === Config.WS_READY_STATE_CLOSING) {
                socket.close();
            }
        } catch (error) {
            console.error('safeCloseWebSocket error', error);
        }
    },
    
    // 发送Telegram消息
    async sendMessage(type, ip, add_data = "") {
        if (!Config.runtime.botToken || !Config.runtime.chatID) return;
        try {
            let msg = "";
            const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
            if (response.ok) {
                const ipInfo = await response.json();
                msg = `${type}\nIP: ${ip}\nCountry: ${ipInfo.country}\n<tg-spoiler>City: ${ipInfo.city}\nOrganization: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
            } else {
                msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
            }
            const url = `https://api.telegram.org/bot${Config.runtime.botToken}/sendMessage?chat_id=${Config.runtime.chatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
            await fetch(url, { method: 'GET' });
        } catch (error) {
            console.error('Error sending message:', error);
        }
    }
};

// ==================== 路由处理器 ====================
const Router = {
    // 路由映射
    routes: {
        '/': 'handleRoot',
        '/config.json': 'handleConfig',
        '/edit': 'handleKV',
        '/bestip': 'handleBestIP',
    },
    
    // 主路由函数
    async handle(request, env, url) {
        let path = url.pathname.toLowerCase();
        const userID = Config.runtime.userID.toLowerCase();
        const dynamicUUID = Config.runtime.dynamicUUID ? Config.runtime.dynamicUUID.toLowerCase() : '';
        
        // 处理路径中的特殊参数
        this.processPathParameters(path);
        
        // 检查是否为 UUID 根路径（订阅请求）
        if (path === `/${userID}` || (dynamicUUID && path === `/${dynamicUUID}`)) {
            return await this.handleSubscription(request, env, url, userID);
        }
        
        // 检查是否为 UUID 前缀路径
        if (path.startsWith(`/${userID}/`) || (dynamicUUID && path.startsWith(`/${dynamicUUID}/`))) {
            const subPath = path.substring(path.indexOf('/', 1));
            const routeKey = this.routes[subPath] || 'handleNotFound';
            return await this[routeKey](request, env, url);
        }
        
        // 检查普通路径
        const routeKey = this.routes[path] || 'handleNotFound';
        return await this[routeKey](request, env, url);
    },
    
    // 处理路径中的特殊参数
    processPathParameters(path) {
        if (/\/socks5=/i.test(path)) {
            Config.runtime.socks5Address = path.split('5=')[1];
        } else if (/\/socks:\/\//i.test(path) || /\/socks5:\/\//i.test(path) || /\/http:\/\//i.test(path)) {
            Config.runtime.enableHttp = path.includes('http://');
            Config.runtime.socks5Address = path.split('://')[1].split('#')[0];
        }
        
        if (/\/proxyip=/i.test(path)) {
            Config.runtime.proxyIP = path.toLowerCase().split('/proxyip=')[1];
        } else if (/\/proxyip\./i.test(path)) {
            Config.runtime.proxyIP = `proxyip.${path.toLowerCase().split("/proxyip.")[1]}`;
        } else if (/\/pyip=/i.test(path)) {
            Config.runtime.proxyIP = path.toLowerCase().split('/pyip=')[1];
        }
    },
    
    async handleRoot(request, env, url) {
        // 发送 Telegram 通知（如果配置了）
        const UA = request.headers.get('User-Agent') || '';
        if (Config.runtime.botToken && Config.runtime.chatID) {
            await Utils.sendMessage(
                `#Get Subscription ${Config.runtime.fileName}`,
                request.headers.get('CF-Connecting-IP') || '',
                `UA: ${UA}</tg-spoiler>\nDomain: ${url.hostname}\n<tg-spoiler>Entry: ${url.pathname + url.search}</tg-spoiler>`
            );
        }
        
        if (env.URL302) return Response.redirect(env.URL302, 302);
        if (env.URL) return await this.proxyURL(env.URL, url);
        
        // 生成固定的时间戳和 token
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);
        const timestamp = Math.ceil(currentDate.getTime() / 1000);
        const fakeUserID = await this.getFakeUserID(Config.runtime.userID, timestamp);
        const token = await Utils.doubleHash(fakeUserID + '');
        
        // 将 token 添加到 URL 参数中
        const fullUrl = new URL(request.url);
        fullUrl.searchParams.set('token', token);
        
        return new Response(await HTMLBuilder.configHtml(fullUrl.searchParams.toString(), env.PROXYHOST || ''), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
    },
    
    async handleConfig(request, env, url) {
        const UA = request.headers.get('User-Agent') || '';
        // 使用相同的时间戳生成 fakeUserID
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);
        const timestamp = Math.ceil(currentDate.getTime() / 1000);
        const fakeUserID = await this.getFakeUserID(Config.runtime.userID, timestamp);
        const token = await Utils.doubleHash(fakeUserID + '');
        
        // 将 token 添加到 URL 参数中
        const configUrl = new URL(request.url);
        configUrl.searchParams.set('token', token);
        
        return await Handlers.config_Json(Config.runtime.userID, request.headers.get('Host'), 'local', UA, Config.runtime.requestProxyIP, configUrl, fakeUserID, '', env, token);
    },
    
    async handleKV(request, env) {
        return await Handlers.KV(request, env, 'ADD.txt');
    },
    
    async handleBestIP(request, env) {
        return await Handlers.bestIP(request, env, 'ADD.txt');
    },
    
    handleNotFound() {
        return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
    },
    
    // 处理订阅请求
    async handleSubscription(request, env, url, userID) {
        const UA = request.headers.get('User-Agent') || 'mozilla';
        const sub = url.searchParams.get('sub') || '';
        let noTLS = url.searchParams.has('notls') ? 'true' : 'false';
        const hostName = request.headers.get('Host') || '';
        
        // 处理代理参数
        let proxyip = Config.runtime.proxyIP;
        if (url.searchParams.has('proxyip')) {
            proxyip = url.searchParams.get('proxyip');
        }
        
        let socks5 = '';
        if (url.searchParams.has('socks5') || url.searchParams.has('socks')) {
            socks5 = url.searchParams.get('socks5') || url.searchParams.get('socks');
        }
        
        let http = '';
        if (url.searchParams.has('http')) {
            http = url.searchParams.get('http');
        }
        
        // 构建代理参数
        let proxyParams = [];
        if (proxyip) proxyParams.push(`proxyip=${encodeURIComponent(proxyip)}`);
        if (socks5) proxyParams.push(`socks5=${encodeURIComponent(socks5)}`);
        if (http) proxyParams.push(`http=${encodeURIComponent(http)}`);
        if (noTLS === 'true') proxyParams.push('notls');
        
        const subProtocol = Config.runtime.subProtocol;
        
        // 生成虚假主机名和用户ID
        const fakeUserID = this.getFakeUserID(userID);
        let fakeHostName = hostName.split('.')[0];
        
        if (hostName.includes('.workers.dev')) {
            noTLS = 'true';
            fakeHostName = `${fakeHostName}.workers.dev`;
        } else if (hostName.includes('.pages.dev')) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (hostName.includes('worker') || hostName.includes('notls') || noTLS === 'true') {
            noTLS = 'true';
            fakeHostName = `notls${fakeHostName}.net`;
        } else {
            fakeHostName = `${fakeHostName}.xyz`;
        }
        
        // 如果没有 sub 参数，则生成本地订阅
        if (!sub || sub === '') {
            try {
                const responseBody = Handlers.generateLocalSubscription(fakeHostName, fakeUserID, noTLS, [], [], [], []);
                return new Response(responseBody, {
                    headers: { 
                        'Content-Type': 'text/plain; charset=utf-8',
                        'Profile-Update-Interval': '6',
                        'Subscription-Userinfo': `upload=0; download=0; total=24*1099511627776; expire=4102329600`
                    }
                });
            } catch (error) {
                console.error('订阅生成错误:', error);
                return new Response('订阅生成失败: ' + error.message, { status: 500 });
            }
        }
        
        // 如果有 sub 参数，调用订阅转换后端
        const subConverter = Config.runtime.subConverter;
        const subConfig = Config.runtime.subConfig;
        const subEmoji = Config.runtime.subEmoji;
        const SCV = Config.runtime.SCV;
        const allowInsecure = Config.runtime.allowInsecure;
        
        let convertedUrl = '';
        let isBase64 = false;
        
        // 根据参数和 User-Agent 确定订阅格式
        if (url.searchParams.has('b64') || url.searchParams.has('base64') || UA.toLowerCase().includes('cf-workers-sub')) {
            isBase64 = true;
        } else if ((UA.toLowerCase().includes('clash') && !UA.toLowerCase().includes('nekobox')) || url.searchParams.has('clash')) {
            convertedUrl = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(sub)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}${allowInsecure}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (UA.toLowerCase().includes('sing-box') || UA.toLowerCase().includes('singbox') || url.searchParams.has('singbox') || url.searchParams.has('sb')) {
            convertedUrl = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(sub)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}${allowInsecure}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (UA.toLowerCase().includes('loon') || url.searchParams.has('loon')) {
            convertedUrl = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(sub)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}${allowInsecure}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else {
            // 默认订阅格式
            convertedUrl = `${subProtocol}://${subConverter}/sub?target=v2ray&url=${encodeURIComponent(sub)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}${allowInsecure}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        }
        
        // 如果是 Base64 订阅，需要获取内容后编码
        if (isBase64) {
            try {
                const response = await fetch(convertedUrl, {
                    headers: { 'User-Agent': 'Mozilla/5.0' }
                });
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const content = await response.text();
                const base64Content = btoa(decodeURIComponent(content));
                return new Response(base64Content, {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="sub.txt"' }
                });
            } catch (error) {
                console.error('订阅转换错误:', error);
                return new Response('订阅转换失败', { status: 500 });
            }
        }
        
        // 其他格式，直接代理转换后的内容
        try {
            const response = await fetch(convertedUrl, {
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return new Response(await response.text(), {
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        } catch (error) {
            console.error('订阅转换错误:', error);
            return new Response('订阅转换失败', { status: 500 });
        }
    },
    
    async proxyURL(proxyUrl, targetUrl) {
        const urlList = await Utils.organizeContent(proxyUrl);
        const fullUrl = urlList[Math.floor(Math.random() * urlList.length)];
        let parsedUrl = new URL(fullUrl);
        
        let protocol = parsedUrl.protocol.slice(0, -1) || 'https';
        let hostname = parsedUrl.hostname;
        let pathname = parsedUrl.pathname;
        let search = parsedUrl.search;
        
        if (pathname.charAt(pathname.length - 1) == '/') pathname = pathname.slice(0, -1);
        pathname += targetUrl.pathname;
        
        let newUrl = `${protocol}://${hostname}${pathname}${search}`;
        let response = await fetch(newUrl);
        let newResponse = new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers
        });
        newResponse.headers.set('X-New-URL', newUrl);
        return newResponse;
    },
    
    async getFakeUserID(userID, timestamp) {
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);
        const dayTimestamp = Math.ceil(currentDate.getTime() / 1000);
        const finalTimestamp = timestamp || dayTimestamp;
        const fakeUserIDMD5 = await crypto.subtle.digest('MD5', new TextEncoder().encode(`${userID}${finalTimestamp}`));
        const fakeUserIDArray = Array.from(new Uint8Array(fakeUserIDMD5));
        const fakeUserIDHex = fakeUserIDArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return [
            fakeUserIDHex.slice(0, 8),
            fakeUserIDHex.slice(8, 12),
            fakeUserIDHex.slice(12, 16),
            fakeUserIDHex.slice(16, 20),
            fakeUserIDHex.slice(20)
        ].join('-');
    }
};

// ==================== 业务处理器 ====================
const Handlers = {
    // 生成本地订阅
    generateLocalSubscription(host, UUID, noTLS, addressesapi, addressescsv, addressesnotlsapi, addressesnotlscsv) {
        const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
        const allAddresses = [...Config.runtime.addresses, ...addressesapi, ...addressescsv];
        let notlsResponseBody = '';
        
        if (noTLS === 'true') {
            const allNotlsAddresses = [...Config.runtime.addressesnotls, ...addressesnotlsapi, ...addressesnotlscsv];
            const uniqueNotlsAddresses = [...new Set(allNotlsAddresses)];

            notlsResponseBody = uniqueNotlsAddresses.map(address => {
                let port = "-1";
                let addressid = address;

                const match = addressid.match(regex);
                if (!match) {
                    if (address.includes(':') && address.includes('#')) {
                        const parts = address.split(':');
                        address = parts[0];
                        const subParts = parts[1].split('#');
                        port = subParts[0];
                        addressid = subParts[1];
                    } else if (address.includes(':')) {
                        const parts = address.split(':');
                        address = parts[0];
                        port = parts[1];
                    } else if (address.includes('#')) {
                        const parts = address.split('#');
                        address = parts[0];
                        addressid = parts[1];
                    }

                    if (addressid.includes(':')) {
                        addressid = addressid.split(':')[0];
                    }
                } else {
                    address = match[1];
                    port = match[2] || port;
                    addressid = match[3] || address;
                }

                if (!Utils.isValidIPv4(address) && port == "-1") {
                    for (let httpPort of Config.HTTP_PORTS) {
                        if (address.includes(httpPort)) {
                            port = httpPort;
                            break;
                        }
                    }
                }
                if (port == "-1") port = "80";

                const fakeDomain = host;
                const finalPath = Config.runtime.path;
                const protocolType = Config.PROTOCOL;

                const ctx = `${protocolType}://${UUID}@${address}:${port}?encryption=none&security=&type=ws&host=${fakeDomain}&path=${encodeURIComponent(finalPath)}#${encodeURIComponent(addressid)}`;

                return ctx;

            }).join('\n');
        }

        const uniqueAddresses = [...new Set(allAddresses)];

        const responseBody = uniqueAddresses.map(address => {
            let port = "-1";
            let addressid = address;

            const match = addressid.match(regex);
            if (!match) {
                if (address.includes(':') && address.includes('#')) {
                    const parts = address.split(':');
                    address = parts[0];
                    const subParts = parts[1].split('#');
                    port = subParts[0];
                    addressid = subParts[1];
                } else if (address.includes(':')) {
                    const parts = address.split(':');
                    address = parts[0];
                    port = parts[1];
                } else if (address.includes('#')) {
                    const parts = address.split('#');
                    address = parts[0];
                    addressid = parts[1];
                }

                if (addressid.includes(':')) {
                    addressid = addressid.split(':')[0];
                }
            } else {
                address = match[1];
                port = match[2] || port;
                addressid = match[3] || address;
            }

            if (!Utils.isValidIPv4(address) && port == "-1") {
                for (let httpsPort of Config.HTTPS_PORTS) {
                    if (address.includes(httpsPort)) {
                        port = httpsPort;
                        break;
                    }
                }
            }
            if (port == "-1") port = "443";

            let fakeDomain = host;
            let finalPath = Config.runtime.path;
            let nodeRemark = '';
            const matchingProxyIP = Config.runtime.proxyIPPool.find(proxyIP => proxyIP.includes(address));
            if (matchingProxyIP) finalPath = `/proxyip=${matchingProxyIP}`;

            const protocolType = Config.PROTOCOL;
            const ctx = `${protocolType}://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${fakeDomain}&fp=random&type=ws&host=${fakeDomain}&path=${encodeURIComponent(finalPath) + Config.runtime.allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(addressid + nodeRemark)}`;

            return ctx;
        }).join('\n');

        let base64Response = responseBody;
        if (noTLS === 'true') base64Response += `\n${notlsResponseBody}`;
        if (Config.runtime.link.length > 0) base64Response += '\n' + Config.runtime.link.join('\n');
        return btoa(base64Response);
    },
    
    // 配置JSON
    async config_Json(userID, hostName, sub, UA, 请求CF反代IP, _url, fakeUserID, fakeHostName, env, token) {
        if (_url.searchParams.get('token') !== token) {
            return new Response('无效的token', { status: 401 });
        }
        
        const newSocks5s = Config.runtime.socks5s.map(addr => {
            if (addr.includes('@')) return addr.split('@')[1];
            else if (addr.includes('//')) return addr.split('//')[1];
            else return addr;
        }).filter(address => address !== '');
        
        let CF访问方法 = "auto";
        if (Config.runtime.enableSocks) CF访问方法 = Config.runtime.enableHttp ? "http" : "socks5";
        else if (Config.runtime.proxyIP && Config.runtime.proxyIP != '') CF访问方法 = "proxyip";
        else if (请求CF反代IP == 'true') CF访问方法 = "auto";
        
        const config = {
            timestamp: new Date().toISOString(),
            config: {
                HOST: hostName,
                UUID: userID ? userID.toLowerCase() : null,
                SCV: Config.runtime.SCV
            },
            proxyip: {
                RequestProxyIP: 请求CF反代IP,
                GO2CF: CF访问方法,
                List: {
                    PROXY_IP: Config.runtime.proxyIPs.filter(ip => ip !== ''),
                    SOCKS5: Config.runtime.enableHttp ? [] : newSocks5s,
                    HTTP: Config.runtime.enableHttp ? newSocks5s : []
                },
                GO2SOCKS5: (Config.runtime.go2Socks5s.includes('all in') || Config.runtime.go2Socks5s.includes('*')) ? ["all in"] : Config.runtime.go2Socks5s
            },
            sub: {
                SUBNAME: Config.runtime.fileName,
                SUB: sub || "local",
                DLS: Config.runtime.DLS,
                CSVREMARK: Config.runtime.remarkIndex,
                SUBAPI: `${Config.runtime.subProtocol}://${Config.runtime.subConverter}`,
                SUBCONFIG: Config.runtime.subConfig,
                ADD: Config.runtime.addresses || [],
                ADDAPI: Config.runtime.addressesapi || [],
                ADDNOTLS: Config.runtime.addressesnotls || [],
                ADDNOTLSAPI: Config.runtime.addressesnotlsapi || [],
                ADDCSV: Config.runtime.addressescsv || []
            },
            KV: env.KV ? true : false,
            UA: UA || null
        };
        
        return new Response(JSON.stringify(config, null, 2), {
            headers: { 'access-control-allow-origin': '*', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' }
        });
    },
    
    // KV管理
    async KV(request, env, txt = 'ADD.txt') {
        try {
            if (request.method === "POST") {
                if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("保存成功");
            }
            
            let content = '';
            if (env.KV) {
                try {
                    content = await env.KV.get(txt) || '';
                } catch (error) {
                    content = '读取数据时发生错误: ' + error.message;
                }
            }
            
            return new Response(await HTMLBuilder.kvEditor(content, !!env.KV), {
                headers: { "Content-Type": "text/html;charset=utf-8" }
            });
        } catch (error) {
            return new Response("服务器错误: " + error.message, { status: 500, headers: { "Content-Type": "text/plain;charset=utf-8" } });
        }
    },
    
    // 最佳IP选择
    async bestIP(request, env, txt = 'ADD.txt') {
        const country = request.cf?.country || 'CN';
        const url = new URL(request.url);
        
        // POST请求处理
        if (request.method === "POST") {
            if (!env.KV) return new Response("未绑定KV空间", { status: 400 });

            try {
                const contentType = request.headers.get('Content-Type');

                // 处理JSON格式的保存/追加请求
                if (contentType && contentType.includes('application/json')) {
                    const data = await request.json();
                    const action = url.searchParams.get('action') || 'save';

                    if (!data.ips || !Array.isArray(data.ips)) {
                        return new Response(JSON.stringify({ error: 'Invalid IP list' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }

                    if (action === 'append') {
                        // 追加模式
                        const existingContent = await env.KV.get(txt) || '';
                        const newContent = data.ips.join('\n');

                        // 合并内容并去重
                        const existingLines = existingContent ?
                            existingContent.split('\n').map(line => line.trim()).filter(line => line) :
                            [];
                        const newLines = newContent.split('\n').map(line => line.trim()).filter(line => line);

                        // 使用Set进行去重
                        const allLines = [...existingLines, ...newLines];
                        const uniqueLines = [...new Set(allLines)];
                        const combinedContent = uniqueLines.join('\n');

                        // 检查合并后的内容大小
                        if (combinedContent.length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({
                                error: `追加失败：合并后内容过大（${(combinedContent.length / 1024 / 1024).toFixed(2)}MB），超过KV存储限制（24MB）`
                            }), {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }

                        await env.KV.put(txt, combinedContent);

                        const addedCount = uniqueLines.length - existingLines.length;
                        const duplicateCount = newLines.length - addedCount;

                        let message = `成功追加 ${addedCount} 个新的优选IP（原有 ${existingLines.length} 个，现共 ${uniqueLines.length} 个）`;
                        if (duplicateCount > 0) {
                            message += `，已去重 ${duplicateCount} 个重复项`;
                        }

                        return new Response(JSON.stringify({
                            success: true,
                            message: message
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                    } else {
                        // 保存模式（覆盖）
                        const content = data.ips.join('\n');
                        
                        // 检查内容大小
                        if (content.length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({
                                error: `保存失败：内容过大（${(content.length / 1024 / 1024).toFixed(2)}MB），超过KV存储限制（24MB）`
                            }), {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }

                        await env.KV.put(txt, content);
                        
                        return new Response(JSON.stringify({
                            success: true,
                            message: `成功保存 ${data.ips.length} 个优选IP`
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                }
            } catch (error) {
                return new Response(JSON.stringify({
                    error: '处理请求时发生错误: ' + error.message
                }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        // GET请求处理
        const action = url.searchParams.get('action');
        
        if (action === 'checkKV') {
            // 检查KV支持
            if (!env.KV) {
                return new Response('No KV', { status: 400 });
            }
            return new Response('KV OK');
        }

        if (action === 'getIPs') {
            // 获取IP列表
            const source = url.searchParams.get('source') || 'official';
            const port = url.searchParams.get('port') || '443';
            
            try {
                const ips = await this.getCFIPs(source, port);
                return new Response(JSON.stringify({ ips: ips }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (error) {
                return new Response(JSON.stringify({ error: error.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        const isChina = country === 'CN';
        const html = await HTMLBuilder.bestIPPage(country, isChina);
        return new Response(html, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    },

    // 获取CF IP列表
    async getCFIPs(ipSource = 'official', targetPort = '443') {
        try {
            let response;
            if (ipSource === 'as13335') {
                // AS13335列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt');
            } else if (ipSource === 'as209242') {
                // AS209242列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt');
            } else if (ipSource === 'as24429') {
                // AS24429列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24429/ipv4-aggregated.txt');
            } else if (ipSource === 'as35916') {
                // AS35916列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35916/ipv4-aggregated.txt');
            } else if (ipSource === 'as199524') {
                // AS199524列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199524/ipv4-aggregated.txt');
            } else if (ipSource === 'cm') {
                // CM整理列表
                response = await fetch('https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt');
            } else if (ipSource === 'proxyip') {
                // 反代IP列表 (直接IP，非CIDR)
                response = await fetch('https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt');
                const text = response.ok ? await response.text() : '';

                // 解析并过滤符合端口的IP
                const allLines = text.split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#'));

                const validIps = [];

                for (const line of allLines) {
                    const parsedIP = this.parseProxyIPLine(line, targetPort);
                    if (parsedIP) {
                        validIps.push(parsedIP);
                    }
                }

                console.log(`反代IP列表解析完成，端口${targetPort}匹配到${validIps.length}个有效IP`);

                // 如果超过512个IP，随机选择512个
                if (validIps.length > 512) {
                    const shuffled = [...validIps].sort(() => 0.5 - Math.random());
                    const selectedIps = shuffled.slice(0, 512);
                    console.log(`IP数量超过512个，随机选择了${selectedIps.length}个IP`);
                    return selectedIps;
                } else {
                    return validIps;
                }
            } else {
                // CF官方列表 (默认)
                response = await fetch('https://www.cloudflare.com/ips-v4/');
            }

            const text = response.ok ? await response.text() : `173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22`;
            const cidrs = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));

            const ips = new Set(); // 使用Set去重
            const targetCount = 512;
            let round = 1;

            // 不断轮次生成IP直到达到目标数量
            while (ips.size < targetCount) {
                console.log(`第${round}轮生成IP，当前已有${ips.size}个`);

                // 每轮为每个CIDR生成指定数量的IP
                for (const cidr of cidrs) {
                    if (ips.size >= targetCount) break;

                    const cidrIPs = this.generateIPsFromCIDR(cidr.trim(), round);
                    cidrIPs.forEach(ip => ips.add(ip));

                    console.log(`CIDR ${cidr} 第${round}轮生成${cidrIPs.length}个IP，总计${ips.size}个`);
                }

                round++;

                // 防止无限循环
                if (round > 100) {
                    console.warn('达到最大轮次限制，停止生成');
                    break;
                }
            }

            console.log(`最终生成${ips.size}个不重复IP`);
            return Array.from(ips).slice(0, targetCount);
        } catch (error) {
            console.error('获取CF IPs失败:', error);
            return [];
        }
    },

    // 解析反代IP行
    parseProxyIPLine(line, targetPort) {
        try {
            // 移除首尾空格
            line = line.trim();
            if (!line) return null;

            let ip = '';
            let port = '';
            let comment = '';

            // 处理注释部分
            if (line.includes('#')) {
                const parts = line.split('#');
                const mainPart = parts[0].trim();
                comment = parts[1].trim();

                // 检查主要部分是否包含端口
                if (mainPart.includes(':')) {
                    const ipPortParts = mainPart.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        // 格式不正确，如":844347.254.171.15:8443"
                        console.warn(`无效的IP:端口格式: ${line}`);
                        return null;
                    }
                } else {
                    // 没有端口，默认443
                    ip = mainPart;
                    port = '443';
                }
            } else {
                // 没有注释
                if (line.includes(':')) {
                    const ipPortParts = line.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        // 格式不正确
                        console.warn(`无效的IP:端口格式: ${line}`);
                        return null;
                    }
                } else {
                    // 只有IP，默认443端口
                    ip = line;
                    port = '443';
                }
            }

            // 验证IP格式
            if (!this.isValidIP(ip)) {
                console.warn(`无效的IP地址: ${ip} (来源行: ${line})`);
                return null;
            }

            // 验证端口格式
            const portNum = parseInt(port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                console.warn(`无效的端口号: ${port} (来源行: ${line})`);
                return null;
            }

            // 检查端口是否匹配
            if (port !== targetPort) {
                return null; // 端口不匹配，过滤掉
            }

            // 构建返回格式
            if (comment) {
                return ip + ':' + port + '#' + comment;
            } else {
                return ip + ':' + port;
            }

        } catch (error) {
            console.error(`解析IP行失败: ${line}`, error);
            return null;
        }
    },

    // 验证IP地址格式
    isValidIP(ip) {
        const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const match = ip.match(ipRegex);

        if (!match) return false;

        // 检查每个数字是否在0-255范围内
        for (let i = 1; i <= 4; i++) {
            const num = parseInt(match[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }

        return true;
    },

    // 从CIDR生成IP
    generateIPsFromCIDR(cidr, count = 1) {
        const [network, prefixLength] = cidr.split('/');
        const prefix = parseInt(prefixLength);

        // 将IP地址转换为32位整数
        const ipToInt = (ip) => {
            return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
        };

        // 将32位整数转换为IP地址
        const intToIP = (int) => {
            return [
                (int >>> 24) & 255,
                (int >>> 16) & 255,
                (int >>> 8) & 255,
                int & 255
            ].join('.');
        };

        const networkInt = ipToInt(network);
        const hostBits = 32 - prefix;
        const numHosts = Math.pow(2, hostBits);

        // 限制生成数量不超过该CIDR的可用主机数
        const maxHosts = numHosts - 2; // -2 排除网络地址和广播地址
        const actualCount = Math.min(count, maxHosts);
        const ips = new Set();

        // 如果可用主机数太少，直接返回空数组
        if (maxHosts <= 0) {
            return [];
        }

        // 生成指定数量的随机IP
        let attempts = 0;
        const maxAttempts = actualCount * 10; // 防止无限循环

        while (ips.size < actualCount && attempts < maxAttempts) {
            const randomOffset = Math.floor(Math.random() * maxHosts) + 1; // +1 避免网络地址
            const randomIP = intToIP(networkInt + randomOffset);
            ips.add(randomIP);
            attempts++;
        }

        return Array.from(ips);
    }
};

// ==================== HTML构建器 ====================
const HTMLBuilder = {
    // 完整配置页面
    async configHtml(urlParams, proxyhost = '') {
        return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title id="pageTitle">配置页面</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f4f7f9;
            --header-bg: #ffffff;
            --card-bg: #ffffff;
            --primary-color: #4a90e2;
            --primary-hover: #357abd;
            --secondary-color: #50e3c2;
            --text-color: #333333;
            --text-light: #666666;
            --border-color: #e0e6ed;
            --shadow-color: rgba(0, 0, 0, 0.08);
            --font-family: 'Noto Sans SC', sans-serif;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--font-family); background-color: var(--bg-color); color: var(--text-color); line-height: 1.7; }
        .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
        .header { position: relative; text-align: center; margin-bottom: 32px; padding: 32px; background-color: var(--header-bg); border-radius: 16px; box-shadow: 0 4px 12px var(--shadow-color); }
        .header h1 { font-size: 2.5rem; font-weight: 700; color: var(--primary-color); margin-bottom: 8px; }
        .header p { font-size: 1.1rem; color: var(--text-light); }
        .loading { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; color: var(--text-light); }
        .spinner { width: 40px; height: 40px; border: 4px solid rgba(0, 0, 0, 0.1); border-top-color: var(--primary-color); border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 16px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .content { display: none; grid-template-columns: 1fr; gap: 32px; }
        .section { background: var(--card-bg); border-radius: 16px; box-shadow: 0 4px 12px var(--shadow-color); overflow: hidden; }
        .section-header { padding: 20px 24px; font-size: 1.25rem; font-weight: 700; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; }
        .section-title { display: flex; align-items: center; gap: 12px; }
        .advanced-settings-btn { background: var(--primary-color); color: white; border: none; border-radius: 8px; padding: 8px 16px; font-size: 0.9rem; font-weight: 500; cursor: pointer; transition: all 0.3s ease; white-space: nowrap; }
        .advanced-settings-btn:hover { background: var(--primary-hover); transform: translateY(-2px); }
        .section-content { padding: 24px; }
        .subscription-grid { display: flex; flex-direction: column; gap: 16px; }
        .subscription-card { background: #fcfdff; border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; transition: all 0.3s ease; }
        .subscription-card:hover { transform: translateY(-2px); box-shadow: 0 8px 16px var(--shadow-color); }
        .subscription-card h4 { color: var(--primary-color); margin-bottom: 12px; font-size: 1.1rem; font-weight: 700; }
        .subscription-link { background: #f4f7f9; border: 1px solid #e0e6ed; border-radius: 8px; padding: 12px; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 0.9rem; margin-bottom: 16px; word-break: break-all; cursor: pointer; color: #333; }
        .button-group { display: flex; gap: 12px; }
        .show-more-btn { margin-top: 16px; padding: 12px 24px; background: var(--primary-color); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 500; transition: all 0.3s ease; }
        .show-more-btn:hover { background: var(--primary-hover); transform: translateY(-2px); }
        .additional-subscriptions { display: none; margin-top: 16px; }
        .additional-subscriptions.show { display: block; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.7); z-index: 10001; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-content { background: white; border-radius: 16px; width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); }
        .modal-header { padding: 24px 24px 0; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); margin-bottom: 24px; }
        .modal-header h3 { margin: 0; color: var(--primary-color); font-size: 1.4rem; font-weight: 700; }
        .modal-close-btn { background: #f0f0f0; border: none; border-radius: 50%; width: 32px; height: 32px; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; transition: all 0.3s ease; }
        .modal-close-btn:hover { background: #e0e0e0; transform: scale(1.1); }
        .modal-body { padding: 0 24px 24px; }
        .setting-item { margin-bottom: 20px; }
        .setting-label { display: flex; align-items: center; cursor: pointer; font-weight: 500; color: var(--text-color); margin-bottom: 8px; position: relative; padding-left: 32px; }
        .setting-label input[type="checkbox"] { position: absolute; opacity: 0; cursor: pointer; left: 0; }
        .checkmark { position: absolute; left: 0; top: 50%; transform: translateY(-50%); height: 20px; width: 20px; background-color: #f0f0f0; border: 2px solid var(--border-color); border-radius: 4px; transition: all 0.3s ease; }
        .setting-label input:checked ~ .checkmark { background-color: var(--primary-color); border-color: var(--primary-color); }
        .setting-label input:checked ~ .checkmark:after { content: ""; position: absolute; display: block; left: 6px; top: 2px; width: 6px; height: 10px; border: solid white; border-width: 0 2px 2px 0; transform: rotate(45deg); }
        .setting-input { width: 100%; padding: 12px 16px; border: 2px solid var(--border-color); border-radius: 8px; font-size: 1rem; transition: all 0.3s ease; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; }
        .setting-input:focus { outline: none; border-color: var(--primary-color); box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.1); }
        .setting-input:disabled { background-color: #f8f9fa; color: #6c757d; cursor: not-allowed; }
        .modal-footer { padding: 24px; border-top: 1px solid var(--border-color); display: flex; justify-content: flex-end; gap: 12px; }
        .modal-btn { padding: 12px 24px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: all 0.3s ease; min-width: 100px; }
        .modal-btn-primary { background: var(--primary-color); color: white; }
        .modal-btn-primary:hover { background: var(--primary-hover); transform: translateY(-2px); }
        .modal-btn-secondary { background: #f8f9fa; color: var(--text-color); border: 1px solid var(--border-color); }
        .modal-btn-secondary:hover { background: #e9ecef; transform: translateY(-2px); }
        .config-grid { display: flex; flex-direction: column; gap: 16px; }
        .footer { text-align: center; padding: 20px; margin-top: 32px; color: var(--text-light); font-size: 0.85rem; border-top: 1px solid var(--border-color); }
        .btn { padding: 10px 16px; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 500; cursor: pointer; transition: all 0.3s ease; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; }
        .btn-primary { background-color: var(--primary-color); color: white; }
        .btn-primary:hover { background-color: var(--primary-hover); transform: translateY(-2px); }
        .btn-secondary { background-color: var(--secondary-color); color: white; }
        .btn-secondary:hover { background-color: #38cba9; transform: translateY(-2px); }
        .details-section details { border-bottom: 1px solid var(--border-color); }
        .details-section details:last-child { border-bottom: none; }
        .details-section summary { padding: 20px 24px; font-size: 1.1rem; font-weight: 500; cursor: pointer; list-style: none; display: flex; justify-content: space-between; align-items: center; position: relative; }
        .summary-content { display: flex; flex-direction: column; gap: 4px; flex: 1; }
        .summary-title { display: flex; align-items: center; gap: 8px; }
        .summary-subtitle { font-size: 0.75rem; font-weight: 400; color: var(--text-light); }
        .summary-actions { display: flex; gap: 8px; align-items: center; margin-right: 20px; }
        .summary-btn { padding: 6px 12px; border: none; border-radius: 6px; font-size: 0.8rem; font-weight: 500; cursor: pointer; transition: all 0.3s ease; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
        .summary-btn.enabled { background-color: var(--primary-color); color: white; }
        .summary-btn.enabled:hover { background-color: var(--primary-hover); transform: translateY(-1px); }
        .summary-btn.disabled { background: #e0e0e0; color: #9e9e9e; cursor: not-allowed; }
        .details-section summary::-webkit-details-marker { display: none; }
        .details-section summary::after { content: '▼'; font-size: 0.8em; transition: transform 0.2s; position: absolute; right: 24px; }
        .details-section details[open] summary::after { transform: rotate(180deg); }
        .details-content { padding: 0 24px 24px; background-color: #fcfdff; }
        .config-card { background: #f8f9fa; border-radius: 8px; padding: 16px; border-left: 4px solid var(--primary-color); }
        .config-label { font-weight: 500; color: var(--text-light); margin-bottom: 4px; font-size: 0.85rem; }
        .config-value { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; word-break: break-all; font-size: 0.9rem; font-weight: 600; color: var(--text-color); }
        .link-card { background: #f8f9fa; border-radius: 12px; padding: 20px; margin-bottom: 16px; border-left: 4px solid var(--secondary-color); }
        .link-card:last-child { margin-bottom: 0; }
        .link-label { font-weight: 700; color: #2a8a73; margin-bottom: 8px; font-size: 1.1rem; }
        .link-content { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 0.9rem; background: #f0f4f8; padding: 12px; border-radius: 8px; word-break: break-all; cursor: pointer; }
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .header { padding: 24px 16px; }
            .header h1 { font-size: 2rem; }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 id="pageHeader">🚀 简单隧道 配置中心</h1>
        </div>
        <div id="loading" class="loading">
            <div class="spinner"></div>
            <p>正在加载配置信息...</p>
        </div>
        <div id="content" class="content">
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span>📋</span>
                        <span>订阅链接</span>
                    </div>
                    <button class="advanced-settings-btn" onclick="openAdvancedSettings()">⚙️ 自定义订阅设置</button>
                </div>
                <div class="section-content">
                    <div class="subscription-grid" id="subscriptionLinks"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="footer"><p id="userAgent"></p></div>
    <div id="advancedModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>⚙️ 自定义订阅设置</h3>
                <button class="modal-close-btn" onclick="closeAdvancedSettings()">×</button>
            </div>
            <div class="modal-body">
                <div class="setting-item">
                    <label class="setting-label">
                        <input type="checkbox" id="subEnabled" onchange="updateSettings()">
                        <span class="checkmark"></span>
                        🚀 优选订阅生成器
                    </label>
                    <input type="text" id="subInput" placeholder="sub.google.com" class="setting-input">
                </div>
                <div class="setting-item">
                    <label class="setting-label">
                        <input type="checkbox" id="proxyipEnabled" onchange="updateProxySettings('proxyip')">
                        <span class="checkmark"></span>
                        🌐 PROXYIP
                    </label>
                    <input type="text" id="proxyipInput" placeholder="proxyip.cmliussss.net:443" class="setting-input">
                </div>
            </div>
            <div class="modal-footer">
                <button class="modal-btn modal-btn-secondary" onclick="closeAdvancedSettings()">返回</button>
                <button class="modal-btn modal-btn-primary" onclick="saveAdvancedSettings()">保存</button>
            </div>
        </div>
    </div>
    <script>
        let configData = null;
        const proxyhost = '${proxyhost}';
        document.addEventListener('DOMContentLoaded', function() { loadConfig(); });
        async function loadConfig() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const token = urlParams.get('token') || '';
                
                // 正确构建 config.json 的 URL
                let configUrl = '/config.json';
                if (window.location.pathname !== '/') {
                    configUrl = window.location.pathname + '/config.json';
                }
                
                const response = await fetch(configUrl + '?token=' + token + '&t=' + Date.now());
                if (!response.ok) throw new Error('HTTP error! status: ' + response.status);
                configData = await response.json();
                document.getElementById('loading').style.display = 'none';
                document.getElementById('content').style.display = 'grid';
                renderSubscriptionLinks();
                document.getElementById('userAgent').textContent = 'User-Agent: ' + configData.UA;
            } catch (error) {
                console.error('加载配置失败:', error);
                document.getElementById('loading').innerHTML = '<p style="color: red;">❌ 加载配置失败，请刷新页面重试</p>';
            }
        }
        function renderSubscriptionLinks() {
            const container = document.getElementById('subscriptionLinks');
            const host = configData.config.HOST;
            const uuid = configData.config.UUID;
            const subscriptions = [
                { name: '自适应订阅', suffix: '?sub', primary: true },
                { name: 'Base64订阅', suffix: '?b64', primary: false }
            ];
            container.innerHTML = '';
            const primarySub = subscriptions.find(sub => sub.primary);
            const primaryUrl = buildSubscriptionUrl(host, uuid, primarySub.suffix);
            const primaryCard = document.createElement('div');
            primaryCard.className = 'subscription-card';
            primaryCard.innerHTML = '<h4>' + primarySub.name + '</h4>' +
                '<div class="subscription-link">' + primaryUrl + '</div>' +
                '<div class="button-group">' +
                    '<button class="btn btn-primary">📋 复制</button>' +
                '</div>';
            primaryCard.querySelector('.subscription-link').addEventListener('click', () => copyText(primaryUrl));
            primaryCard.querySelector('.btn-primary').addEventListener('click', () => copyText(primaryUrl));
            container.appendChild(primaryCard);
        }
        function buildSubscriptionUrl(host, uuid, suffix) {
            let baseUrl = 'https://${proxyhost}' + host + '/' + uuid + suffix;
            const settings = getAdvancedSettings();
            const params = [];
            if (settings.subEnabled && settings.subValue) {
                if (suffix === '?sub') {
                    baseUrl = 'https://${proxyhost}' + host + '/' + uuid + '?sub=' + encodeURIComponent(settings.subValue);
                } else {
                    params.push('sub=' + encodeURIComponent(settings.subValue));
                }
            }
            if (settings.proxyipEnabled && settings.proxyipValue) {
                params.push('proxyip=' + encodeURIComponent(settings.proxyipValue));
            }
            if (params.length > 0) {
                const separator = baseUrl.includes('?') ? '&' : '?';
                return baseUrl + separator + params.join('&');
            }
            return baseUrl;
        }
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('✅ 已复制到剪贴板');
            }).catch(err => {
                console.error('复制失败:', err);
                showToast('❌ 复制失败');
            });
        }
        function showToast(message, duration = 3000) {
            const toast = document.createElement('div');
            toast.style.cssText = 'position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: rgba(0, 0, 0, 0.7); color: white; padding: 12px 24px; border-radius: 8px; z-index: 10000; font-weight: 500; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => { toast.remove(); }, duration);
        }
        function openAdvancedSettings() {
            document.getElementById('advancedModal').classList.add('show');
            loadAdvancedSettings();
        }
        function closeAdvancedSettings() {
            document.getElementById('advancedModal').classList.remove('show');
        }
        function loadAdvancedSettings() {
            const settings = getAdvancedSettings();
            document.getElementById('subEnabled').checked = settings.subEnabled;
            document.getElementById('subInput').value = settings.subValue;
            document.getElementById('subInput').disabled = !settings.subEnabled;
            document.getElementById('proxyipEnabled').checked = settings.proxyipEnabled;
            document.getElementById('proxyipInput').value = settings.proxyipValue;
            document.getElementById('proxyipInput').disabled = !settings.proxyipEnabled;
        }
        function getAdvancedSettings() {
            const settings = localStorage.getItem('advancedSubscriptionSettings');
            if (settings) return JSON.parse(settings);
            return {
                subEnabled: false,
                subValue: '',
                proxyipEnabled: false,
                proxyipValue: ''
            };
        }
        function saveAdvancedSettings() {
            const settings = {
                subEnabled: document.getElementById('subEnabled').checked,
                subValue: document.getElementById('subInput').value,
                proxyipEnabled: document.getElementById('proxyipEnabled').checked,
                proxyipValue: document.getElementById('proxyipInput').value
            };
            localStorage.setItem('advancedSubscriptionSettings', JSON.stringify(settings));
            closeAdvancedSettings();
            renderSubscriptionLinks();
            showToast('🎉 设置已保存！请重新复制上方更新后的订阅链接', 5000);
        }
        function updateSettings() {
            const enabled = document.getElementById('subEnabled').checked;
            document.getElementById('subInput').disabled = !enabled;
        }
        function updateProxySettings(type) {
            const enabled = document.getElementById(type + 'Enabled').checked;
            if (enabled) {
                const proxyTypes = ['proxyip'];
                proxyTypes.forEach(proxyType => {
                    if (proxyType !== type) {
                        document.getElementById(proxyType + 'Enabled').checked = false;
                        document.getElementById(proxyType + 'Input').disabled = true;
                    }
                });
            }
            document.getElementById(type + 'Input').disabled = !enabled;
        }
    </script>
</body>
</html>`;
    },
    
    // Nginx默认页面
    async nginx() {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to nginx!</title>
    <style>
        body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
    </style>
</head>
<body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, nginx web server is successfully installed and working.</p>
    <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
</body>
</html>`;
    },
    
    // KV编辑器
    async kvEditor(content, hasKV) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>优选订阅列表</title>
    <meta charset="utf-8">
    <style>
        body { margin: 0; padding: 15px; font-size: 13px; }
        .editor { width: 100%; height: 520px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-family: monospace; }
        .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .save-btn { background: #4CAF50; color: white; }
        .back-btn { background: #666; color: white; }
    </style>
</head>
<body>
    <h3>优选订阅列表</h3>
    ${hasKV ? `
        <textarea class="editor" id="content">${content}</textarea>
        <div>
            <button class="btn back-btn" onclick="window.location.href=window.location.pathname.replace(/\\/[^/]*$/, '')">返回</button>
            <button class="btn save-btn" onclick="saveContent()">保存</button>
        </div>
        <script>
            async function saveContent() {
                const content = document.getElementById('content').value;
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: content,
                        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
                    });
                    if (response.ok) alert('保存成功');
                    else alert('保存失败');
                } catch (error) {
                    alert('保存失败: ' + error.message);
                }
            }
        </script>
    ` : '<p>未绑定KV空间</p>'}
</body>
</html>`;
    },
    
    // 最佳IP页面(完整版)
    async bestIPPage(country, isChina) {
        // 判断是否为中国用户
        const countryDisplayClass = isChina ? '' : 'proxy-warning';
        const countryDisplayText = isChina ? `${country}` : `${country} ⚠️`;

        return `
<!DOCTYPE html>
<html>
<head>
    <title>Cloudflare IP优选</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            width: 80%;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
            padding: 20px;
        }
        .ip-list {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            max-height: 400px;
            overflow-y: auto;
        }
        .ip-item {
            margin: 2px 0;
            font-family: monospace;
        }
        .stats {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .test-info {
            margin-top: 15px;
            padding: 12px;
            background-color: #f3e5f5;
            border: 1px solid #ce93d8;
            border-radius: 6px;
            color: #4a148c;
        }
        .test-info p {
            margin: 0;
            font-size: 14px;
            line-height: 1.5;
        }
        .proxy-warning {
            color: #d32f2f !important;
            font-weight: bold !important;
            font-size: 1.1em;
        }
        .warning-notice {
            background-color: #ffebee;
            border: 2px solid #f44336;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            color: #c62828;
        }
        .warning-notice h3 {
            margin: 0 0 10px 0;
            color: #d32f2f;
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .warning-notice p {
            margin: 8px 0;
            line-height: 1.5;
        }
        .warning-notice ul {
            margin: 10px 0 10px 20px;
            line-height: 1.6;
        }
        .test-controls {
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        .port-selector {
            margin: 10px 0;
        }
        .port-selector label {
            font-weight: bold;
            margin-right: 10px;
        }
        .port-selector select {
            padding: 5px 10px;
            font-size: 14px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        .button-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 15px;
        }
        .test-button {
            background-color: #4CAF50;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .test-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .save-button {
            background-color: #2196F3;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .save-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .save-button:not(:disabled):hover {
            background-color: #1976D2;
        }
        .append-button {
            background-color: #FF9800;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .append-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .append-button:not(:disabled):hover {
            background-color: #F57C00;
        }
        .edit-button {
            background-color: #9C27B0;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .edit-button:hover {
            background-color: #7B1FA2;
        }
        .back-button {
            background-color: #607D8B;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .back-button:hover {
            background-color: #455A64;
        }
        .save-warning {
            margin-top: 10px;
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            border-radius: 6px;
            padding: 12px;
            color: #e65100;
            font-weight: bold;
        }
        .save-warning small {
            font-size: 14px;
            line-height: 1.5;
            display: block;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            display: none;
        }
        .message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .progress {
            width: 100%;
            background-color: #f0f0f0;
            border-radius: 5px;
            margin: 10px 0;
        }
        .progress-bar {
            width: 0%;
            height: 20px;
            background-color: #4CAF50;
            border-radius: 5px;
            transition: width 0.3s;
        }
        .good-latency { color: #4CAF50; font-weight: bold; }
        .medium-latency { color: #FF9800; font-weight: bold; }
        .bad-latency { color: #f44336; font-weight: bold; }
        .show-more-section {
            text-align: center;
            margin: 10px 0;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 5px;
        }
        .show-more-btn {
            background-color: #607D8B;
            color: white;
            padding: 8px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        .show-more-btn:hover {
            background-color: #455A64;
        }
        .ip-display-info {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        .save-tip {
            margin-top: 15px;
            padding: 12px;
            background-color: #e8f5e8;
            border: 1px solid #4CAF50;
            border-radius: 6px;
            color: #2e7d32;
            font-size: 14px;
            line-height: 1.5;
        }
        .save-tip strong {
            color: #1b5e20;
        }
        .warm-tips {
            margin: 20px 0;
            padding: 15px;
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            border-radius: 8px;
            color: #e65100;
        }
        .warm-tips h3 {
            margin: 0 0 10px 0;
            color: #f57c00;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .warm-tips p {
            margin: 8px 0;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <h1>Cloudflare IP优选</h1>
    
    <div class="stats">
        <p>您的国家: <span class="${countryDisplayClass}">${countryDisplayText}</span></p>
        ${!isChina ? `
        <div class="warning-notice">
            <h3>⚠️ 代理状态警告</h3>
            <p>检测到您可能处于代理状态，这可能会影响测试结果的准确性。</p>
            <p>建议：</p>
            <ul>
                <li>尽量在本地网络环境下进行测试</li>
                <li>关闭VPN或代理软件</li>
                <li>使用直连网络进行测试</li>
            </ul>
        </div>
        ` : ''}
    </div>

    <div class="test-controls">
        <div class="port-selector">
            <label for="portSelect">测试端口:</label>
            <select id="portSelect">
                <option value="80">80 (HTTP)</option>
                <option value="443" selected>443 (HTTPS)</option>
                <option value="2053">2053</option>
                <option value="2083">2083</option>
                <option value="2087">2087</option>
                <option value="2096">2096</option>
                <option value="8443">8443</option>
            </select>
        </div>
        
        <div class="button-group">
            <button class="test-button" id="startTest">开始测试</button>
            <button class="save-button" id="saveAll" disabled>保存全部</button>
            <button class="append-button" id="appendTop" disabled>追加前20个</button>
            <button class="edit-button" onclick="window.location.href=window.location.pathname.replace(/\\/[^/]*$/, '') + '/kv'">编辑订阅列表</button>
            <button class="back-button" onclick="window.location.href=window.location.pathname.replace(/\\/[^/]*$/, '')">返回</button>
        </div>
        
        <div class="save-warning" id="saveWarning" style="display: none;">
            <small>⚠️ 保存功能需要绑定KV存储空间。请确保您的Worker已正确配置KV命名空间。</small>
        </div>
    </div>

    <div class="progress">
        <div class="progress-bar" id="progressBar"></div>
    </div>

    <div class="message" id="message"></div>

    <div class="ip-list" id="ipList">
        <p>请点击"开始测试"按钮进行IP优选测试...</p>
    </div>

    <div class="test-info">
        <p><strong>测试说明：</strong></p>
        <p>• 测试基于TCP连接延迟进行排序</p>
        <p>• 绿色延迟表示优秀（&lt;100ms）</p>
        <p>• 橙色延迟表示良好（100-200ms）</p>
        <p>• 红色延迟表示较差（&gt;200ms）</p>
        <p>• 测试结果仅作参考，实际使用效果可能因网络环境而异</p>
    </div>

    <div class="warm-tips">
        <h3>💡 温馨提示</h3>
        <p>• 测试过程中请不要关闭页面</p>
        <p>• 测试结果会实时更新，请耐心等待</p>
        <p>• 建议选择"追加前20个"功能，避免覆盖原有数据</p>
        <p>• 如需保存所有结果，请确保KV存储空间充足</p>
    </div>

    <script>
        let testResults = [];
        let totalIPs = 0;
        let testedIPs = 0;
        let isTesting = false;

        // 显示消息
        function showMessage(text, type = 'success') {
            const messageEl = document.getElementById('message');
            messageEl.textContent = text;
            messageEl.className = 'message ' + type;
            messageEl.style.display = 'block';
            setTimeout(() => {
                messageEl.style.display = 'none';
            }, 5000);
        }

        // 更新进度条
        function updateProgress() {
            const progressBar = document.getElementById('progressBar');
            const progress = testedIPs / totalIPs * 100;
            progressBar.style.width = progress + '%';
        }

        // 测试单个IP的延迟
        async function testIP(ip, port) {
            const startTime = performance.now();
            
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);
                
                const response = await fetch(`https://${ip}:${port}`, {
                    method: 'HEAD',
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                const endTime = performance.now();
                const latency = Math.round(endTime - startTime);
                
                return { ip, port, latency, success: true };
            } catch (error) {
                return { ip, port, latency: 9999, success: false };
            }
        }

        // 获取CF IP列表
        async function getCFIPs(source = 'official', port = '443') {
            try {
                const response = await fetch(window.location.pathname + '?action=getIPs&source=' + source + '&port=' + port);
                if (response.ok) {
                    const data = await response.json();
                    return data.ips || [];
                }
            } catch (error) {
                console.error('获取IP列表失败:', error);
            }
            return [];
        }

        // 开始测试
        async function startTest() {
            if (isTesting) return;
            
            const port = document.getElementById('portSelect').value;
            const startButton = document.getElementById('startTest');
            const saveButton = document.getElementById('saveAll');
            const appendButton = document.getElementById('appendTop');
            
            startButton.disabled = true;
            isTesting = true;
            testResults = [];
            testedIPs = 0;
            
            showMessage('正在获取IP列表...', 'success');
            
            // 获取IP列表
            const ips = await getCFIPs('official', port);
            totalIPs = ips.length;
            
            if (ips.length === 0) {
                showMessage('获取IP列表失败，请重试', 'error');
                startButton.disabled = false;
                isTesting = false;
                return;
            }
            
            showMessage(`开始测试${ips.length}个IP，请稍候...`, 'success');
            
            // 分批测试，避免阻塞
            const batchSize = 10;
            const ipListEl = document.getElementById('ipList');
            ipListEl.innerHTML = '<p>测试中...请稍候</p>';
            
            for (let i = 0; i < ips.length; i += batchSize) {
                const batch = ips.slice(i, i + batchSize);
                const batchPromises = batch.map(ip => testIP(ip, port));
                
                const batchResults = await Promise.all(batchPromises);
                testResults.push(...batchResults);
                testedIPs += batch.length;
                
                updateProgress();
                
                // 实时更新显示
                const sortedResults = [...testResults]
                    .sort((a, b) => a.latency - b.latency)
                    .slice(0, 50); // 只显示前50个
                
                displayResults(sortedResults);
                
                // 短暂延迟，避免过于频繁的更新
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            
            // 最终排序
            testResults.sort((a, b) => a.latency - b.latency);
            displayResults(testResults.slice(0, 100)); // 显示前100个
            
            showMessage(`测试完成！共测试${testResults.length}个IP`, 'success');
            startButton.disabled = false;
            saveButton.disabled = false;
            appendButton.disabled = false;
            isTesting = false;
        }

        // 显示测试结果
        function displayResults(results) {
            const ipListEl = document.getElementById('ipList');
            
            if (results.length === 0) {
                ipListEl.innerHTML = '<p>暂无测试结果</p>';
                return;
            }
            
            let html = `<div class="ip-display-info">显示 ${results.length} 个最优IP (延迟从低到高排序)</div>`;
            
            results.forEach((result, index) => {
                const latencyClass = result.latency < 100 ? 'good-latency' : 
                                   result.latency < 200 ? 'medium-latency' : 'bad-latency';
                const statusIcon = result.success ? '✅' : '❌';
                
                html += `<div class="ip-item">
                    <span>${index + 1}. ${result.ip}:${result.port}</span>
                    <span class="${latencyClass}">${result.latency}ms</span>
                    <span>${statusIcon}</span>
                </div>`;
            });
            
            ipListEl.innerHTML = html;
        }

        // 保存IP列表
        async function saveIPs(action = 'save') {
            if (testResults.length === 0) {
                showMessage('没有测试结果可保存', 'error');
                return;
            }
            
            const validResults = testResults.filter(r => r.success).slice(0, 100);
            const ips = validResults.map(r => `${r.ip}:${r.port}`);
            
            try {
                const response = await fetch(window.location.pathname, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action: action,
                        ips: ips
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showMessage(result.message || '保存成功', 'success');
                } else {
                    const error = await response.json();
                    showMessage(error.error || '保存失败', 'error');
                }
            } catch (error) {
                showMessage('保存失败: ' + error.message, 'error');
            }
        }

        // 绑定事件
        document.getElementById('startTest').addEventListener('click', startTest);
        document.getElementById('saveAll').addEventListener('click', () => saveIPs('save'));
        document.getElementById('appendTop').addEventListener('click', () => saveIPs('append'));

        // 检查KV支持
        fetch(window.location.pathname + '?action=checkKV').then(response => {
            if (response.status === 400) {
                document.getElementById('saveWarning').style.display = 'block';
            }
        }).catch(() => {
            document.getElementById('saveWarning').style.display = 'block';
        });
    </script>
</body>
</html>`
    }
};

// ==================== 主入口 ====================
export default {
    async fetch(request, env, ctx) {
        try {
            // 初始化配置
            Config.init(env);
            
            // 验证用户ID
            if (env.KEY || env.TOKEN || (Config.runtime.userID && !Utils.isValidUUID(Config.runtime.userID))) {
                Config.runtime.dynamicUUID = env.KEY || env.TOKEN || Config.runtime.userID;
                const userIDs = await Utils.generateDynamicUUID(Config.runtime.dynamicUUID);
                Config.runtime.userID = userIDs[0];
                Config.runtime.userIDLow = userIDs[1];
            } else {
                Config.runtime.dynamicUUID = Config.runtime.userID;
            }
            
            if (!Config.runtime.userID) {
                return new Response('请设置你的UUID变量', { status: 404, headers: { "Content-Type": "text/plain;charset=utf-8" } });
            }
            
            // 加载列表数据
            await Config.loadLists(env);
            
            // 设置代理相关
            Config.runtime.proxyIP = Config.runtime.proxyIPs.length > 0 ? Config.runtime.proxyIPs[Math.floor(Math.random() * Config.runtime.proxyIPs.length)] : '';
            Config.runtime.socks5Address = Config.runtime.socks5s.length > 0 ? Config.runtime.socks5s[Math.floor(Math.random() * Config.runtime.socks5s.length)] : '';
            Config.runtime.enableHttp = env.HTTP ? true : (Config.runtime.socks5Address ? Config.runtime.socks5Address.toLowerCase().includes('http://') : false);
            Config.runtime.socks5Address = Config.runtime.socks5Address ? Config.runtime.socks5Address.split('//')[1] || Config.runtime.socks5Address : '';
            Config.runtime.requestProxyIP = env.RPROXYIP || !Config.runtime.proxyIP ? 'true' : 'false';
            
            // 处理SOCKS5解析
            if (Config.runtime.socks5Address) {
                try {
                    Config.runtime.parsedSocks5 = Utils.socks5AddressParser(Config.runtime.socks5Address);
                    Config.runtime.enableSocks = true;
                    Config.runtime.requestProxyIP = env.RPROXYIP || 'false';
                } catch (err) {
                    Config.runtime.enableSocks = false;
                    Config.runtime.requestProxyIP = env.RPROXYIP || !Config.runtime.proxyIP ? 'true' : 'false';
                }
            }
            
            const url = new URL(request.url);
            const upgradeHeader = request.headers.get('Upgrade');
            
            // WebSocket处理
            if (upgradeHeader && upgradeHeader === 'websocket') {
                return await WebSocketHandler.handle(request, url);
            }
            
            // HTTP请求路由
            return await Router.handle(request, env, url);
            
        } catch (err) {
            console.error('Error:', err);
            return new Response(err.toString(), { status: 500 });
        }
    }
};

// ==================== WebSocket处理器 ====================
const WebSocketHandler = {
    async handle(request, url) {
        const webSocketPair = new WebSocketPair();
        const [client, webSocket] = Object.values(webSocketPair);
        webSocket.accept();
        
        const remoteSocketWrapper = { value: null };
        const log = (info, event = '') => console.log(`[${url.pathname}] ${info}`, event);
        const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
        const readableWebSocketStream = this.makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
        
        readableWebSocketStream.pipeTo(new WritableStream({
            async write(chunk) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }
                
                const { hasError, message, addressRemote, portRemote, rawDataIndex, isUDP } = this.processVlessHeader(chunk, Config.runtime.userID);
                if (hasError) throw new Error(message);
                if (isUDP && portRemote !== 53) throw new Error('UDP proxy only enabled for DNS');
                
                const vlessResponseHeader = new Uint8Array([0, 0]);
                const rawClientData = chunk.slice(rawDataIndex);
                
                if (portRemote === 53) {
                    const { write } = await this.handleUDPOutBound(webSocket, vlessResponseHeader, log);
                    write(rawClientData);
                    return;
                }
                
                this.handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
            },
            close() { log('WebSocket closed'); },
            abort(reason) { log('WebSocket abort', JSON.stringify(reason)); }
        })).catch((err) => log('Pipeline error', err));
        
        return new Response(null, { status: 101, webSocket: client });
    },
    
    makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
        let readableStreamCancel = false;
        return new ReadableStream({
            start(controller) {
                webSocketServer.addEventListener('message', (event) => {
                    if (readableStreamCancel) return;
                    controller.enqueue(event.data);
                });
                
                webSocketServer.addEventListener('close', () => {
                    Utils.safeCloseWebSocket(webSocketServer);
                    if (!readableStreamCancel) controller.close();
                });
                
                webSocketServer.addEventListener('error', (err) => {
                    log('WebSocket错误');
                    controller.error(err);
                });
                
                const { earlyData, error } = Utils.base64ToArrayBuffer(earlyDataHeader);
                if (error) controller.error(error);
                else if (earlyData) controller.enqueue(earlyData);
            },
            cancel(reason) {
                if (readableStreamCancel) return;
                log(`流被取消: ${reason}`);
                readableStreamCancel = true;
                Utils.safeCloseWebSocket(webSocketServer);
            }
        });
    },
    
    processVlessHeader(vlessBuffer, userID) {
        if (vlessBuffer.byteLength < 24) {
            return { hasError: true, message: 'invalid data' };
        }
        
        const userIDArray = new Uint8Array(vlessBuffer.slice(1, 17));
        const userIDString = Array.from(userIDArray).map(b => b.toString(16).padStart(2, '0')).join('');
        const userId = [
            userIDString.slice(0, 8),
            userIDString.slice(8, 12),
            userIDString.slice(12, 16),
            userIDString.slice(16, 20),
            userIDString.slice(20)
        ].join('-');
        
        if (userId !== userID && (!Config.runtime.userIDLow || userId !== Config.runtime.userIDLow)) {
            return { hasError: true, message: 'invalid user' };
        }
        
        const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
        const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
        
        if (command === 1) {
            // TCP
        } else if (command === 2) {
            return { hasError: true, message: 'UDP not supported except DNS' };
        } else {
            return { hasError: true, message: 'invalid command' };
        }
        
        const portIndex = 18 + optLength + 1;
        const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
        const portRemote = new DataView(portBuffer).getUint16(0);
        
        const addressBuffer = new Uint8Array(vlessBuffer.slice(portIndex + 2, portIndex + 3));
        const addressType = addressBuffer[0];
        let addressValue = '';
        
        if (addressType === 1) {
            addressValue = new Uint8Array(vlessBuffer.slice(portIndex + 3, portIndex + 7)).join('.');
        } else if (addressType === 2) {
            const addressLength = new Uint8Array(vlessBuffer.slice(portIndex + 3, portIndex + 4))[0];
            addressValue = new TextDecoder().decode(vlessBuffer.slice(portIndex + 4, portIndex + 4 + addressLength));
        } else {
            return { hasError: true, message: 'invalid address type' };
        }
        
        return {
            hasError: false,
            addressRemote: addressValue,
            portRemote,
            rawDataIndex: portIndex + 3 + (addressType === 2 ? new Uint8Array(vlessBuffer.slice(portIndex + 3, portIndex + 4))[0] + 1 : 4),
            isUDP: command === 2
        };
    },
    
    async handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
        const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
        remoteSocket.value = tcpSocket;
        
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState !== Config.WS_READY_STATE_OPEN) {
                    throw new Error('WebSocket not open');
                }
                if (vlessResponseHeader) {
                    webSocket.send(await new Blob([vlessResponseHeader, chunk]).arrayBuffer());
                    vlessResponseHeader = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() { log(`TCP connection closed`); },
            abort(reason) { log(`TCP connection abort`, reason); }
        })).catch((error) => {
            console.error('TCP error:', error);
            Utils.safeCloseWebSocket(webSocket);
        });
    },
    
    async handleUDPOutBound(webSocket, vlessResponseHeader, log) {
        const transformStream = new TransformStream({
            transform(chunk, controller) {
                for (let index = 0; index < chunk.byteLength;) {
                    const lengthBuffer = chunk.slice(index, index + 2);
                    const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                    const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                    index = index + 2 + udpPacketLength;
                    controller.enqueue(udpData);
                }
            }
        });
        
        transformStream.readable.pipeTo(new WritableStream({
            async write(chunk) {
                const resp = await fetch('https://1.1.1.1/dns-query', {
                    method: 'POST',
                    headers: { 'content-type': 'application/dns-message' },
                    body: chunk
                });
                const dnsQueryResult = await resp.arrayBuffer();
                const udpSize = dnsQueryResult.byteLength;
                const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
                
                if (webSocket.readyState === Config.WS_READY_STATE_OPEN) {
                    log(`DNS query successful, size: ${udpSize}`);
                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    vlessResponseHeader = null;
                }
            }
        })).catch((error) => log('DNS error', error));
        
        const writer = transformStream.writable.getWriter();
        return { write: (chunk) => writer.write(chunk) };
    }
};
