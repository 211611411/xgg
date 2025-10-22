export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const {
                method
            } = request;
            const {
                pathname
            } = url;

            const headers = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Cache-Control': 'no-cache'
            };

            if (method === 'OPTIONS') {
                return new Response(null, {
                    headers
                });
            }

            if (method === 'POST' && pathname === '/api/register') {
                return await handleRegister(request, env);
            }

            if (method === 'POST' && pathname === '/api/login') {
                return await handleLogin(request, env);
            }

            if (method === 'PUT' && pathname === '/api/user/nickname') {
                return await handleUpdateNickname(request, env);
            }

            if (method === 'GET' && pathname.startsWith('/api/user/')) {
                return await handleGetUserInfo(request, env, url);
            }

            if (method === 'POST' && pathname === '/api/message') {
                return await handlePostMessage(request, env);
            }

            if (method === 'GET' && pathname === '/api/messages') {
                return await handleGetMessages(request, env, url);
            }

            if (method === 'DELETE' && pathname === '/api/messages') {
                return await handleClearMessages(request, env);
            }

            if (method === 'GET' && pathname === '/api/users/online') {
                return await handleGetOnlineUsers(request, env);
            }

            if (method === 'POST' && pathname === '/api/user/heartbeat') {
                return await handleHeartbeat(request, env);
            }

            if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
                return serveHTML();
            }

            return new Response('Not Found', {
                status: 404,
                headers
            });

        } catch (error) {
            console.error('全局错误:', error);
            return createResponse({
                error: '服务器内部错误'
            }, 500);
        }
    }
};

addEventListener('scheduled', event => {
    event.waitUntil(Promise.all([
        checkOfflineUsers(),
        cleanupIPLimits()
    ]));
});

async function cleanupIPLimits() {
    try {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        await env.DB.prepare('DELETE FROM ip_limits WHERE created_at < ?').bind(thirtyDaysAgo).run();
        console.log('定时任务: 已清理过期的IP限制记录');
    } catch (error) {
        console.error('清理IP限制记录错误:', error);
    }
}

async function checkOfflineUsers() {
    try {
        const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();
        await env.DB.prepare('UPDATE users SET online = 0 WHERE last_login < ? AND online = 1').bind(oneMinuteAgo).run();
        console.log('定时任务: 已更新离线用户状态');
    } catch (error) {
        console.error('定时任务错误:', error);
    }
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function validateQQ(qq) {
    return /^\d{5,12}$/.test(qq);
}

function validateNickname(nickname) {
    const trimmed = nickname.trim();
    return trimmed.length > 0 && trimmed.length <= 20;
}

function validatePassword(password) {
    return password.length >= 6 && password.length <= 20;
}

function validateMessage(message) {
    const trimmed = message.trim();
    return trimmed.length > 0 && trimmed.length <= 1000;
}

function createResponse(data, status = 200, customHeaders = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache',
        ...customHeaders
    };

    return new Response(JSON.stringify(data), {
        status,
        headers
    });
}

async function checkUserLimits(env, qq, ip) {
    const now = new Date();
    const today = now.toISOString().split('T')[0];

    const user = await env.DB.prepare('SELECT last_message_time FROM users WHERE qq = ?').bind(qq).first();
    if (user && user.last_message_time) {
        const lastMessageTime = new Date(user.last_message_time);
        const timeDiff = (now - lastMessageTime) / (1000 * 60);

        if (timeDiff < 5) {
            return {
                allowed: false,
                reason: `发送频率过快，请等待 ${Math.ceil(5 - timeDiff)} 分钟后再发送`
            };
        }
    }

    if (ip) {
        const ipRecord = await env.DB.prepare('SELECT last_register_date FROM ip_limits WHERE ip = ?')
            .bind(ip).first();

        if (ipRecord && ipRecord.last_register_date) {
            const lastRegisterDate = new Date(ipRecord.last_register_date);
            const daysDiff = (now - lastRegisterDate) / (1000 * 60 * 60 * 24);

            if (daysDiff < 30) {
                const remainingDays = Math.ceil(30 - daysDiff);
                return {
                    allowed: false,
                    reason: `每个IP地址30天内只能注册一个账号，请等待 ${remainingDays} 天后再注册`
                };
            }
        }
    }

    return {
        allowed: true
    };
}

async function parseJSONRequest(request) {
    const contentType = request.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
        throw new Error('请使用 application/json 格式');
    }
    return await request.json();
}

async function handleRegister(request, env) {
    try {
        const {
            qq,
            nickname,
            password
        } = await parseJSONRequest(request);

        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

        const ipLimit = await checkIPRegisterLimit(env, clientIP);
        if (!ipLimit.allowed) {
            return createResponse({
                error: ipLimit.reason
            }, 429);
        }

        if (!validateQQ(qq)) {
            return createResponse({
                error: 'QQ号码必须是5-12位数字'
            }, 400);
        }

        if (!validateNickname(nickname)) {
            return createResponse({
                error: '昵称不能为空且不能超过20个字符'
            }, 400);
        }

        if (!validatePassword(password)) {
            return createResponse({
                error: '密码长度必须在6-20位之间'
            }, 400);
        }

        const existingUser = await env.DB.prepare('SELECT qq FROM users WHERE qq = ?').bind(qq).first();
        if (existingUser) {
            return createResponse({
                error: '该QQ号码已被注册'
            }, 409);
        }

        const passwordHash = await hashPassword(password);
        const now = new Date().toISOString();
        const today = new Date().toISOString().split('T')[0];

        await env.DB.prepare('INSERT INTO users (qq, nickname, password_hash, created_at, last_login, online, register_ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .bind(qq, nickname.trim(), passwordHash, now, now, 0, clientIP)
            .run();

        await updateIPRegisterLimit(env, clientIP, today);

        return createResponse({
            message: '注册成功',
            user: {
                qq,
                nickname
            }
        });

    } catch (error) {
        console.error('注册错误:', error);
        return createResponse({
            error: error.message || '注册失败'
        }, 400);
    }
}

async function checkIPRegisterLimit(env, ip) {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const ipRecord = await env.DB.prepare('SELECT register_count, last_register_date FROM ip_limits WHERE ip = ?')
        .bind(ip).first();

    if (ipRecord) {
        if (ipRecord.last_register_date >= thirtyDaysAgo && ipRecord.register_count >= 1) {
            return {
                allowed: false,
                reason: '每个IP地址每30天只能注册一个账号'
            };
        }
    }

    return {
        allowed: true
    };
}

async function updateIPRegisterLimit(env, ip) {
    const today = new Date().toISOString().split('T')[0];
    const existing = await env.DB.prepare('SELECT ip FROM ip_limits WHERE ip = ?').bind(ip).first();

    if (existing) {
        await env.DB.prepare('UPDATE ip_limits SET register_count = 1, last_register_date = ? WHERE ip = ?')
            .bind(today, ip).run();
    } else {
        await env.DB.prepare('INSERT INTO ip_limits (ip, register_count, last_register_date, created_at) VALUES (?, ?, ?, ?)')
            .bind(ip, 1, today, new Date().toISOString()).run();
    }
}

async function handleLogin(request, env) {
    try {
        const {
            qq,
            password
        } = await parseJSONRequest(request);

        if (!qq || !password) {
            return createResponse({
                error: '请填写完整信息'
            }, 400);
        }

        const user = await env.DB.prepare('SELECT qq, nickname, password_hash FROM users WHERE qq = ?').bind(qq).first();

        if (!user) {
            return createResponse({
                error: '用户不存在'
            }, 404);
        }

        const passwordHash = await hashPassword(password);
        if (user.password_hash !== passwordHash) {
            return createResponse({
                error: '密码错误'
            }, 401);
        }

        const now = new Date().toISOString();
        await env.DB.prepare('UPDATE users SET last_login = ?, online = 1 WHERE qq = ?').bind(now, qq).run();

        return createResponse({
            message: '登录成功',
            user: {
                qq: user.qq,
                nickname: user.nickname
            }
        });

    } catch (error) {
        console.error('登录错误:', error);
        return createResponse({
            error: error.message || '登录失败'
        }, 400);
    }
}

async function handleUpdateNickname(request, env) {
    try {
        const {
            qq,
            nickname
        } = await parseJSONRequest(request);

        if (!qq || !nickname) {
            return createResponse({
                error: '参数不完整'
            }, 400);
        }

        if (!validateNickname(nickname)) {
            return createResponse({
                error: '昵称不能为空且不能超过20个字符'
            }, 400);
        }

        const result = await env.DB.prepare('UPDATE users SET nickname = ? WHERE qq = ?').bind(nickname.trim(), qq).run();

        if (result.changes === 0) {
            return createResponse({
                error: '用户不存在'
            }, 404);
        }

        return createResponse({
            message: '昵称修改成功',
            user: {
                qq,
                nickname
            }
        });

    } catch (error) {
        console.error('更新昵称错误:', error);
        return createResponse({
            error: error.message || '更新失败'
        }, 400);
    }
}

async function handleGetUserInfo(request, env, url) {
    try {
        const qq = url.pathname.split('/')[3];

        if (!qq) {
            return createResponse({
                error: 'QQ号码不能为空'
            }, 400);
        }

        const user = await env.DB.prepare('SELECT qq, nickname, created_at, last_login, online FROM users WHERE qq = ?').bind(qq).first();

        if (!user) {
            return createResponse({
                error: '用户不存在'
            }, 404);
        }

        return createResponse({
            user: {
                qq: user.qq,
                nickname: user.nickname,
                created_at: user.created_at,
                last_login: user.last_login,
                online: user.online
            }
        });

    } catch (error) {
        console.error('获取用户信息错误:', error);
        return createResponse({
            error: error.message || '获取失败'
        }, 400);
    }
}

async function handlePostMessage(request, env) {
    try {
        const {
            qq,
            content
        } = await parseJSONRequest(request);

        if (!qq || !content) {
            return createResponse({
                error: '参数不完整'
            }, 400);
        }

        if (!validateMessage(content)) {
            return createResponse({
                error: '消息内容不能为空且不能超过1000个字符'
            }, 400);
        }

        const user = await env.DB.prepare('SELECT qq, nickname, last_message_time FROM users WHERE qq = ?').bind(qq).first();
        if (!user) {
            return createResponse({
                error: '用户不存在'
            }, 404);
        }

        const now = new Date();
        if (user.last_message_time) {
            const lastMessageTime = new Date(user.last_message_time);
            const timeDiff = (now - lastMessageTime) / (1000 * 60);

            if (timeDiff < 5) {
                const waitTime = Math.ceil(5 - timeDiff);
                return createResponse({
                    error: `发送频率过快，请等待 ${waitTime} 分钟后再发送`
                }, 429);
            }
        }

        const nickname = user.nickname;
        const messageId = generateId();
        const nowISO = now.toISOString();
        const today = nowISO.split('T')[0];

        await env.DB.prepare('INSERT INTO messages (id, qq, content, created_at) VALUES (?, ?, ?, ?)')
            .bind(messageId, qq, content.trim(), nowISO).run();

        await env.DB.prepare('UPDATE users SET last_message_time = ? WHERE qq = ?')
            .bind(nowISO, qq).run();

        return createResponse({
            message: '发送成功',
            message_id: messageId,
            nickname: nickname
        });

    } catch (error) {
        console.error('发送消息错误:', error);
        return createResponse({
            error: error.message || '发送失败'
        }, 400);
    }
}

async function handleGetMessages(request, env, url) {
    try {
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const messages = await env.DB.prepare(`
            SELECT 
                m.id, 
                m.qq, 
                u.nickname, 
                m.content, 
                m.created_at 
            FROM 
                messages m
            JOIN 
                users u ON m.qq = u.qq
            ORDER BY 
                m.created_at DESC
            LIMIT ? OFFSET ?
        `).bind(limit, offset).all();

        const formattedMessages = messages.results.map(msg => ({
            ...msg,
            created_at: new Date(msg.created_at).toISOString()
        })).reverse();

        return createResponse({
            messages: formattedMessages,
            count: formattedMessages.length
        });

    } catch (error) {
        console.error('获取消息错误:', error);
        return createResponse({
            error: error.message || '获取失败'
        }, 400);
    }
}

async function handleClearMessages(request, env) {
    try {
        await env.DB.prepare('DELETE FROM messages').run();

        return createResponse({
            message: '消息已清空'
        });

    } catch (error) {
        console.error('清空消息错误:', error);
        return createResponse({
            error: error.message || '清空失败'
        }, 400);
    }
}

async function handleGetOnlineUsers(request, env) {
    try {
        const fiveMinutesAgo = new Date(Date.now() - 30 * 1000).toISOString();

        const users = await env.DB.prepare('SELECT DISTINCT qq, nickname FROM users WHERE last_login > ? AND online = 1 ORDER BY last_login DESC').bind(fiveMinutesAgo).all();

        return createResponse({
            users: users.results,
            count: users.results.length
        });

    } catch (error) {
        console.error('获取在线用户错误:', error);
        return createResponse({
            error: error.message || '获取失败'
        }, 400);
    }
}

async function handleHeartbeat(request, env) {
    try {
        const {
            qq
        } = await parseJSONRequest(request);
        const now = new Date().toISOString();

        await env.DB.prepare('UPDATE users SET last_login = ?, online = 1 WHERE qq = ?').bind(now, qq).run();

        return createResponse({
            message: '心跳成功'
        });
    } catch (error) {
        console.error('心跳失败:', error);
        return createResponse({
            error: '心跳失败'
        }, 400);
    }
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

import htmlContent from './index.html';

function serveHTML() {
    return new Response(htmlContent, {
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=300'
        }
    });
}