// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: green; icon-glyph: bolt;

// ==========================================
// 1. 数据配置区
// ==========================================
const CONFIG = {
    // 账号密码
    username: "xxxxx",
    password: "xxxxx", // ⚠️ 请替换为真实密码

    // 宿舍具体参数
    type: "IEC",
    level: "3",
    feeitemid: "448",
    xiaoyu_id: "3&沁园",
    loudong_id: "23&沁园30号栋",
    room_id: "4186&135",

    // OCR 识别接口
    ocrApiUrl: "http://xxxxxxx:7777/classification",
    
    // 强制登录开关 (测试时 true，稳定后 false)
    forceLogin: false, 

    // --- 视觉阈值配置 ---
    ROOM_CAPACITY: 100,    
    WARNING_THRESHOLD: 50, 
    DANGER_THRESHOLD: 10,  
};

const BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
};

// ==========================================
// 2. 全局认证中心 (CAS)
// ==========================================
class NuistCAS {
    constructor(username, password) {
        this.username = username;
        this.password = password;
        this.cookies = {};
        this.loginUrl = "https://authserver.nuist.edu.cn/authserver/login?service=https%3A%2F%2Ficard.nuist.edu.cn%2Fberserker-auth%2Fcas%2Flogin%2Fwisedu%3FtargetUrl%3Dhttps%3A%2F%2Ficard.nuist.edu.cn%2Fplat%2F%3Fname%3DloginTransit";
    }

    _updateCookies(request) {
        if (request.response && request.response.cookies) {
            request.response.cookies.forEach(c => {
                this.cookies[c.name] = c.value;
            });
        }
    }

    getCookieString() {
        return Object.keys(this.cookies).map(k => `${k}=${this.cookies[k]}`).join("; ");
    }

    async logout() {
        console.log("🧹 [CAS] 清理历史登录状态...");
        let req = new Request("https://authserver.nuist.edu.cn/authserver/logout");
        req.headers = { ...BASE_HEADERS };
        await req.loadString();
        this.cookies = {}; 
    }

    async getLoginParams() {
        console.log("🚪 [CAS] 访问大门，获取加密参数...");
        let req = new Request(this.loginUrl);
        req.headers = { ...BASE_HEADERS };
        let html = await req.loadString();
        this._updateCookies(req); 
        
        let finalUrl = req.response ? req.response.url : "";
        
        // 如果已经携带 ticket，说明处于登录态
        if (finalUrl.includes("ticket=")) {
            let ticket = finalUrl.match(/ticket=([^&]+)/)[1];
            return { ticket: ticket };
        }

        let executionMatch = html.match(/(?:id|name)="execution"\s+value="([^"]+)"/i) || html.match(/value="([^"]+)"\s+(?:id|name)="execution"/i);
        let pwdSaltMatch = html.match(/(?:id|name)="pwdEncryptSalt"\s+value="([^"]+)"/i) || html.match(/(?:id|name)="pwdDefaultEncryptSalt"\s+value="([^"]+)"/i) || html.match(/value="([^"]+)"\s+(?:id|name)="pwdDefaultEncryptSalt"/i) || html.match(/value="([^"]+)"\s+(?:id|name)="pwdEncryptSalt"/i);
        
        if (!executionMatch || !pwdSaltMatch) throw new Error("无法获取 execution 或 pwdSalt，系统可能已更新");
        
        return { execution: executionMatch[1], salt: pwdSaltMatch[1] };
    }

    async getAndRecognizeCaptcha() {
        console.log("🧩 [验证码] 获取并识别验证码...");
        let req = new Request("https://authserver.nuist.edu.cn/authserver/getCaptcha.htl?" + Date.now());
        req.headers = { ...BASE_HEADERS, "Cookie": this.getCookieString() };
        let captchaImg = await req.loadImage();
        this._updateCookies(req); 
        
        if (!CONFIG.ocrApiUrl) return "";
        
        try {
            let ocrReq = new Request(CONFIG.ocrApiUrl);
            ocrReq.method = "POST";
            ocrReq.headers = { "Content-Type": "application/json" };
            ocrReq.body = JSON.stringify({ image: Data.fromPNG(captchaImg).toBase64String() });
            
            let ocrRes = await ocrReq.loadJSON();
            let resultText = ocrRes.result ? ocrRes.result.trim() : "";
            console.log(`📝 [验证码] 识别结果: ${resultText}`);
            return resultText;
        } catch (e) {
            throw new Error(`OCR识别失败: ${e.message}`);
        }
    }

    async encryptPassword(pwd, salt) {
        console.log("🔐 [CAS] 加密密码...");
        let html = `<!DOCTYPE html><html><head><script src="https://cdn.staticfile.net/crypto-js/4.1.1/crypto-js.min.js"></script></head><body></body></html>`;
        let wv = new WebView();
        await wv.loadHTML(html);
        
        let js = `
            let timer = setInterval(() => {
                if (typeof CryptoJS !== 'undefined') {
                    clearInterval(timer);
                    try {
                        let chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
                        let res = '';
                        for(let i=0; i<64; i++) res += chars.charAt(Math.floor(Math.random()*chars.length));
                        let text = res + '${pwd}';
                        
                        res = '';
                        for(let i=0; i<16; i++) res += chars.charAt(Math.floor(Math.random()*chars.length));
                        let ivStr = res;
                        
                        let key = CryptoJS.enc.Utf8.parse('${salt}');
                        let iv = CryptoJS.enc.Utf8.parse(ivStr);
                        let encrypted = CryptoJS.AES.encrypt(text, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                        completion(encrypted.toString());
                    } catch(e) { completion("ERROR:" + e.message); }
                }
            }, 50);
        `;
        let result = await wv.evaluateJavaScript(js, true);
        if (result && result.startsWith("ERROR:")) throw new Error(result);
        return result;
    }

    async submitLogin(params, captchaText, encryptedPwd) {
        console.log("🔑 [CAS] 提交登录表单...");
        let req = new Request(this.loginUrl);
        req.method = "POST";
        req.headers = { 
            ...BASE_HEADERS, 
            "Cookie": this.getCookieString(), 
            "Content-Type": "application/x-www-form-urlencoded" 
        };
        req.body = `username=${encodeURIComponent(this.username)}&password=${encodeURIComponent(encryptedPwd)}&captcha=${captchaText}&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&lt=&execution=${encodeURIComponent(params.execution)}`;
        
        // 拦截重定向机制
        req.onRedirect = function(request) { return null; };
        let reqBody = await req.loadString();
        this._updateCookies(req);
        
        let locationUrl = req.response.headers["Location"] || req.response.headers["location"];
        if (!locationUrl || !locationUrl.includes("ticket=")) {
            let errorMsg = reqBody.match(/<span id="showErrorTip"[^>]*>([\s\S]*?)<\/span>/i) || reqBody.match(/class="auth_error"[^>]*>([\s\S]*?)<\//i);
            throw new Error("登录失败: " + (errorMsg ? errorMsg[1].replace(/<[^>]+>/g, '').trim() : "验证码或密码错误"));
        }

        // 跟随重定向获取业务 Ticket
        console.log("🔗 [CAS] 追溯跳转链获取业务 Ticket...");
        let currentUrl = locationUrl;
        let authCode = null;
        for(let i=0; i<3; i++) {
            let reqHop = new Request(currentUrl);
            reqHop.method = "GET";
            reqHop.headers = { ...BASE_HEADERS, "Cookie": this.getCookieString() };
            reqHop.onRedirect = function() { return null; };
            try { await reqHop.loadString(); } catch(e) {}
            this._updateCookies(reqHop);
            
            let nextLoc = reqHop.response.headers["Location"] || reqHop.response.headers["location"];
            if (!nextLoc) break;
            currentUrl = nextLoc;
            
            if (currentUrl.includes("loginTransit") && currentUrl.includes("ticket=")) {
                authCode = currentUrl.match(/ticket=([^&]+)/)[1];
                break;
            }
        }

        if (!authCode) throw new Error("重定向失败，未拿到内部 Ticket");
        console.log("✅ [CAS] 登录成功！取得全局业务 Ticket。");
        return authCode;
    }

    async login() {
        if (CONFIG.forceLogin) await this.logout();
        
        let params = await this.getLoginParams();
        if (params.ticket) {
            console.log("✅ [CAS] 处于活跃状态，秒级免密登录。");
            return params.ticket; 
        }

        let captcha = await this.getAndRecognizeCaptcha();
        if (!captcha) throw new Error("验证码环节中断");

        let encPwd = await this.encryptPassword(this.password, params.salt);
        let ticket = await this.submitLogin(params, captcha, encPwd);
        return ticket;
    }
}

// ==========================================
// 3. 一卡通业务模块 (ICard)
// ==========================================
class NuistICard {
    constructor(casInstance, icardConfig) {
        this.cas = casInstance; // 继承 CAS 的 Cookie 等状态
        this.config = icardConfig;
        this.accessToken = null;
    }

    async authorize(ticket) {
        console.log("🎫 [一卡通] 使用 Ticket 兑换 Access Token...");
        let req = new Request("https://icard.nuist.edu.cn/berserker-auth/oauth/token");
        req.method = "POST";
        req.headers = {
            ...BASE_HEADERS,
            "Cookie": this.cas.getCookieString(),
            "Authorization": "Basic bW9iaWxlX3NlcnZpY2VfcGxhdGZvcm06bW9iaWxlX3NlcnZpY2VfcGxhdGZvcm1fc2VjcmV0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://icard.nuist.edu.cn/plat/loginTransit",
            "Origin": "https://icard.nuist.edu.cn"
        };
        req.body = `username=${ticket}&password=${ticket}&grant_type=password&scope=all&loginFrom=h5&logintype=sso&device_token=h5&synAccessSource=h5`;
        
        let res = await req.loadJSON();
        if (!res.access_token) throw new Error("获取 Access Token 失败");
        
        this.accessToken = res.access_token;
        console.log("🎉 [一卡通] Token 兑换成功！具备查询权限。");
        return true;
    }

    async getElectricityBalance() {
        if (!this.accessToken) throw new Error("未授权，请先获取 Access Token");

        console.log("⚡ [一卡通] 请求电费数据接口...");
        let req = new Request("https://icard.nuist.edu.cn/charge/feeitem/getThirdData");
        req.method = "POST";
        req.headers = {
            ...BASE_HEADERS,
            "Cookie": this.cas.getCookieString(),
            "Content-Type": "application/x-www-form-urlencoded",
            "synjones-auth": `bearer ${this.accessToken}`,
            "Origin": "https://icard.nuist.edu.cn",
            "Referer": "https://icard.nuist.edu.cn/",
            "synAccessSource": "pc"
        };
        
        req.body = `type=${encodeURIComponent(this.config.type)}&level=${encodeURIComponent(this.config.level)}&feeitemid=${encodeURIComponent(this.config.feeitemid)}&xiaoyu_id=${encodeURIComponent(this.config.xiaoyu_id)}&loudong_id=${encodeURIComponent(this.config.loudong_id)}&room_id=${encodeURIComponent(this.config.room_id)}`;
        
        let res = await req.loadJSON();
        let balance = res.map?.showData?.['剩余电量'] || res.data?.showData?.['剩余电量'];
        
        if (balance === undefined || balance === null) throw new Error("无法解析接口返回的电费数据");
        
        let bName = this.config.loudong_id.includes("&") ? this.config.loudong_id.split("&")[1] : this.config.loudong_id;
        let rName = this.config.room_id.includes("&") ? this.config.room_id.split("&")[1] : this.config.room_id;
        console.log(`💰 [一卡通] ${bName} ${rName} 剩余电量：${balance} 度`);
        
        return parseFloat(balance);
    }
}

// ==========================================
// 4. Widget 视觉绘制
// ==========================================
class WidgetUI {
    static create(currentPower, updateTimeStr, isError = false) {
        const widget = new ListWidget();
        widget.setPadding(14, 14, 12, 14); 

        const maxPower = CONFIG.ROOM_CAPACITY;
        let bName = CONFIG.loudong_id.includes("&") ? CONFIG.loudong_id.split("&")[1] : CONFIG.loudong_id;
        let rName = CONFIG.room_id.includes("&") ? CONFIG.room_id.split("&")[1] : CONFIG.room_id;
        const roomName = `${bName} ${rName}`;

        let themeColor, baseBg, trackColor, labelColor, iconBgColor, iconStrokeColor;
        if (currentPower <= CONFIG.DANGER_THRESHOLD) {
            themeColor = new Color("#ff3b30"); 
            baseBg = new Color("#7a1515");     
            trackColor = new Color("#4a0b0b"); 
            labelColor = new Color("#e08484"); 
            iconBgColor = new Color("#8c1f1f"); 
            iconStrokeColor = new Color("#d96464"); 
        } else if (currentPower <= CONFIG.WARNING_THRESHOLD) {
            themeColor = new Color("#ff9500");
            baseBg = new Color("#965a00");
            trackColor = new Color("#593400");
            labelColor = new Color("#e0b884");
            iconBgColor = new Color("#a86805");
            iconStrokeColor = new Color("#d9a364");
        } else {
            themeColor = new Color("#1df33c"); 
            baseBg = new Color("#0d6110");
            trackColor = new Color("#0a420b");
            labelColor = new Color("#86b583");
            iconBgColor = new Color("#165a19");
            iconStrokeColor = new Color("#549353");
        }

        const bgSize = 400; 
        const bgCtx = new DrawContext();
        bgCtx.size = new Size(bgSize, bgSize);
        bgCtx.opaque = false;
        bgCtx.setFillColor(baseBg);
        bgCtx.fillRect(new Rect(0, 0, bgSize, bgSize));

        const fadeHeight = bgSize * 0.7; 
        for (let y = 0; y < fadeHeight; y += 4) {
            let alpha = 0.07 * (1 - (y / fadeHeight));
            bgCtx.setFillColor(new Color("#ffffff", Math.max(0, alpha)));
            for (let x = 0; x < bgSize; x += 32) {
                bgCtx.fillRect(new Rect(x, y, 16, 4));
            }
        }
        widget.backgroundImage = bgCtx.getImage();

        let mainStack = widget.addStack();
        mainStack.layoutVertically();

        let topStack = mainStack.addStack();
        topStack.layoutHorizontally();

        let textStack = topStack.addStack();
        textStack.layoutVertically();

        let title1 = textStack.addText(roomName);
        title1.font = Font.systemFont(11);
        title1.textColor = labelColor;
        title1.lineLimit = 1;
        title1.minimumScaleFactor = 0.8; 

        textStack.addSpacer(2);
        let title2 = textStack.addText("POWER");
        title2.font = Font.blackSystemFont(11);
        title2.textColor = themeColor;

        textStack.addSpacer(2);
        let valStack = textStack.addStack();
        valStack.bottomAlignContent();
        
        let displayPower = isError && currentPower === 0 ? "--" : currentPower.toFixed(1);
        let valText = valStack.addText(displayPower);
        valText.font = Font.boldSystemFont(34); 
        valText.textColor = Color.white();
        valText.minimumScaleFactor = 0.6; 

        let unitText = valStack.addText(" 度");
        unitText.font = Font.boldSystemFont(14);
        unitText.textColor = Color.white();

        topStack.addSpacer();

        let iconBgStack = topStack.addStack();
        iconBgStack.size = new Size(32, 32);
        iconBgStack.cornerRadius = 16;
        iconBgStack.backgroundColor = iconBgColor;
        iconBgStack.centerAlignContent();

        let sfSymbol = SFSymbol.named("bolt.fill");
        let iconImg = iconBgStack.addImage(sfSymbol.image);
        iconImg.imageSize = new Size(16, 16);
        iconImg.tintColor = iconStrokeColor;

        mainStack.addSpacer(); 

        let labelStack = mainStack.addStack();
        labelStack.layoutHorizontally();

        let l0 = labelStack.addText("0");
        l0.font = Font.boldSystemFont(11);
        l0.textColor = labelColor;
        labelStack.addSpacer();

        let l50 = labelStack.addText(Math.round(maxPower/2).toString());
        l50.font = Font.boldSystemFont(11);
        l50.textColor = labelColor;
        labelStack.addSpacer();

        let l100 = labelStack.addText(maxPower.toString());
        l100.font = Font.boldSystemFont(11);
        l100.textColor = labelColor;

        mainStack.addSpacer(4);

        const barWidth = 240, barHeight = 48, barRadius = 24;  
        const barCtx = new DrawContext();
        barCtx.size = new Size(barWidth, barHeight);
        barCtx.opaque = false;

        barCtx.setFillColor(trackColor);
        const trackPath = new Path();
        trackPath.addRoundedRect(new Rect(0, 0, barWidth, barHeight), barRadius, barRadius);
        barCtx.addPath(trackPath);
        barCtx.fillPath();

        let ratio = Math.min(Math.max(currentPower / maxPower, 0), 1);
        let fillWidth = barWidth * ratio;

        if (fillWidth > barRadius) { 
            barCtx.setFillColor(themeColor);
            const fillPath = new Path();
            fillPath.addRoundedRect(new Rect(0, 0, fillWidth, barHeight), barRadius, barRadius);
            barCtx.addPath(fillPath);
            barCtx.fillPath();
        } else if (fillWidth > 0) {
            barCtx.setFillColor(themeColor);
            const minPath = new Path();
            minPath.addRoundedRect(new Rect(0, 0, fillWidth, barHeight), fillWidth/2, fillWidth/2);
            barCtx.addPath(minPath);
            barCtx.fillPath();
        }

        let progressImg = mainStack.addImage(barCtx.getImage());
        progressImg.applyFittingContentMode();
        progressImg.centerAlignImage();

        mainStack.addSpacer(4);
        let timeStack = mainStack.addStack();
        timeStack.layoutHorizontally();
        timeStack.addSpacer(); 

        let timeIcon = SFSymbol.named(isError ? "exclamationmark.triangle.fill" : "arrow.clockwise");
        let timeIconImg = timeStack.addImage(timeIcon.image);
        timeIconImg.imageSize = new Size(9, 9);
        timeIconImg.tintColor = isError ? Color.red() : labelColor;
        timeStack.addSpacer(3);

        let timeStr = timeStack.addText(updateTimeStr);
        timeStr.font = Font.systemFont(9);
        timeStr.textColor = isError ? Color.red() : labelColor;

        return widget;
    }
}

// ==========================================
// 🚀 5. 主程序入口
// ==========================================
async function main() {
    let balance = 0;
    let errorMessage = null;
    let isError = false;

    try {
        // 初始化大厅
        const cas = new NuistCAS(CONFIG.username, CONFIG.password);
        
        // 步骤1：登录并拿到 Ticket
        const ticket = await cas.login();
        
        // 步骤2：初始化一卡通并授权
        const icard = new NuistICard(cas, CONFIG);
        await icard.authorize(ticket);
        
        // 步骤3：查询余额
        balance = await icard.getElectricityBalance();
        
    } catch (e) {
        console.error(`❌ 程序执行异常: ${e.message}`);
        errorMessage = e.message;
        isError = true;
    }

    // 处理时间与UI更新
    const df = new DateFormatter();
    df.dateFormat = "MM-dd HH:mm";
    let timeString = df.string(new Date());
    
    if (isError) {
        timeString = "Err: " + errorMessage.substring(0, 12) + "...";
    }

    // 绘制并呈现组件
    config.widgetFamily = 'small';
    const widget = WidgetUI.create(balance, timeString, isError);
    
    // 强制 30 分钟刷新机制
    widget.refreshAfterDate = new Date(Date.now() + 1000 * 60 * 30);
    Script.setWidget(widget);

    if (!config.runsInWidget) {
        await widget.presentSmall();
    }
    Script.complete();
}

// 启动执行
await main();
