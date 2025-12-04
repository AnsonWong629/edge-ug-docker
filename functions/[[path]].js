import JSEncrypt from 'jsencrypt'

const Database = {
    // 修复：接收 nas 对象作为参数
    async getObject(nas, key) {
        if (!nas) return null;
        const value = await nas.get(key)
        if (value == null) {
            return null
        }
        return JSON.parse(value)
    },
    async setObject(nas, key, value) {
        if (!nas) return;
        if (value == null) {
            await nas.delete(key)
        } else {
            await nas.put(key, JSON.stringify(value))
        }
    }
}

const CookieHelper = {
    getSetCookieObject(response) {
        const cookieObject = {}
        const setCookie = response.headers.getSetCookie()
        if (setCookie) {
            for (let cookieStr of setCookie) {
                const [key, value] = cookieStr.split(';')[0].split('=')
                cookieObject[key] = value
            }
        }
        return cookieObject
    },
    getCookieObject(cookieStr) {
        const cookieObject = {}
        if (cookieStr == null) {
            return cookieObject
        }
        const cookieArr = cookieStr.split('; ')
        for (let cookie of cookieArr) {
            const cookieObj = cookie.split('=')
            cookieObject[cookieObj[0]] = decodeURIComponent(cookieObj[1])
        }
        return cookieObject
    },
    getCookieStr(cookieObject) {
        const cookieArr = []
        if (cookieObject) {
            for (let key of Object.keys(cookieObject)) {
                cookieArr.push(key + '=' + encodeURIComponent(cookieObject[key]))
            }
        }
        return cookieArr.join('; ')
    }
}

const getUGreenLink = async ctx => {
    const config = ctx.config
    const aliasUrl = new URL('https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias')
    const response = await fetch(aliasUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alias: config.alias})
    })
    const res = await response.json()
    if (!res.data) throw new Error("获取绿联Link失败，请检查别名是否正确")
    return 'https://' + config.alias + '.' + res.data.relayDomain
}

const getPublicKey = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/verify/check')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            username: config.username
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const base64Str = response.headers.get('x-rsa-token')
    return atob(base64Str)
}

const getPassword = async ctx => {
    const config = ctx.config
    const encryptor = new JSEncrypt()
    encryptor.setPublicKey(ctx.publicKey)
    return encryptor.encrypt(config.password)
}

const login = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/verify/login')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            is_simple: true,
            keepalive: true,
            otp: true,
            username: config.username,
            password: ctx.password
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const json = await response.json()
    return json.data
}

const getDockerToken = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/gateway/proxy/dockerToken')
    url.searchParams.set('token', ctx.token)
    url.searchParams.set('port', config.port)
    const response = await fetch(url)
    const json = await response.json()
    if (!json.data) throw new Error("获取Docker Token失败")
    return json.data['redirect_url']
}

const getProxyInfo = async ctx => {
    const response = await fetch(ctx.dockerToken, {
        method: 'GET',
        redirect: 'manual',
    })
    const origin = new URL(ctx.dockerToken).origin
    const cookieObject = CookieHelper.getSetCookieObject(response)
    const token = cookieObject['ugreen-proxy-token']
    return {origin, token}
}

const proxy = async (request, origin, token) => {
    const requestUrl = new URL(request.url)
    // 修复：确保替换正确
    const targetUrl = new URL(request.url.replace(requestUrl.origin, origin))
    
    const targetHeaders = new Headers(request.headers)
    targetHeaders.set('host', targetUrl.host)
    
    const cookieObject = CookieHelper.getCookieObject(request.headers.get('cookie'))
    cookieObject['ugreen-proxy-token'] = token
    targetHeaders.set('cookie', CookieHelper.getCookieStr(cookieObject))
    
    const response = await fetch(targetUrl, {
        method: request.method,
        headers: targetHeaders,
        body: request.body,
        redirect: 'manual'
    })
    
    // 弱化错误检查，防止误杀
    if (response.status === 302 && response.headers.get('location')?.includes('errorPage')) {
         throw new Error('访问错误，跳转到了错误页')
    }
    
    return response
}

export async function onRequest(context) {
    const request = context.request
    const env = context.env
    const config = {
        alias: env.UG_ALIAS,
        username: env.UG_USERNAME,
        password: env.UG_PASSWORD,
        port: env.UG_PORT
    }
    
    if (!config.alias || !config.username) {
         return new Response("环境变量未配置", {status: 500})
    }

    const ctx = {}
    const key = config.alias + ':' + config.port
    
    try {
        // 修复：必须传入 env.nas
        const cache = await Database.getObject(env.nas, key)
        if (cache) {
            const response = await proxy(request, cache.origin, cache.token)
            // 确保不报错
            if (response.status !== 500) {
                const newRes = new Response(response.body, response)
                newRes.headers.set('x-edge-kv', 'hit')
                return newRes
            }
        }
    } catch (error) {
        console.log('缓存访问出错', error)
    }
    
    ctx.config = config
    try {
        ctx.link = await getUGreenLink(ctx)
        ctx.publicKey = await getPublicKey(ctx)
        ctx.password = await getPassword(ctx)
        const loginInfo = await login(ctx)
        if (!loginInfo) throw new Error("登录失败")
        
        ctx.token = loginInfo.token
        ctx.dockerToken = await getDockerToken(ctx)
        const proxyInfo = await getProxyInfo(ctx)
        ctx.proxyOrigin = proxyInfo.origin
        ctx.proxyToken = proxyInfo.token
        const response = await proxy(request, ctx.proxyOrigin, ctx.proxyToken)
        
        const newRes = new Response(response.body, response)
        newRes.headers.set('x-edge-kv', 'miss')
        
        // 修复：必须传入 env.nas
        await Database.setObject(env.nas, key, {origin: ctx.proxyOrigin, token: ctx.proxyToken})
        return newRes
    } catch (error) {
        console.log('error', error)
        return new Response(`访问出错: ${error.message}`, {status: 500})
    }
}
