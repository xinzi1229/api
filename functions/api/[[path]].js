// --- 腾讯云 COS 签名算法 V3 实现 ---

async function hmacSha256(key, msg) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const msgData = encoder.encode(msg);
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    return signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(msg) {
    const encoder = new TextEncoder();
    const data = encoder.encode(msg);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSignatureKey(secretKey, date, service, region) {
    const kDate = await hmacSha256(date, secretKey);
    const kService = await hmacSha256(service, kDate);
    const kRegion = await hmacSha256(region, kService);
    const kSigning = await hmacSha256('tc3_request', kRegion);
    return kSigning;
}

async function getCosAuthorization(request, secretId, secretKey, service, region) {
    const method = request.method;
    const url = new URL(request.url);
    const pathname = url.pathname;
    const query = url.search;
    const headers = request.headers;

    const canonicalHeaders = [];
    const signedHeaders = [];
    for (const [key, value] of headers) {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'host' || lowerKey === 'content-type') {
            canonicalHeaders.push(`${lowerKey}:${value.trim()}`);
            signedHeaders.push(lowerKey);
        }
    }
    canonicalHeaders.sort();
    signedHeaders.sort();

    const bodyClone = request.clone();
    const hashedPayload = await sha256(await bodyClone.text());

    const canonicalRequest = [
        method,
        pathname,
        query,
        canonicalHeaders.join('\n') + '\n',
        signedHeaders.join(';'),
        hashedPayload
    ].join('\n');

    const now = new Date();
    const timestamp = Math.floor(now.getTime() / 1000);
    const date = now.toISOString().substr(0, 10).replace(/-/g, '');
    const credentialScope = `${date}/${service}/${region}/tc3_request`;
    
    const hashedCanonicalRequest = await sha256(canonicalRequest);
    const stringToSign = [
        'TC3-HMAC-SHA256',
        now.toISOString().replace(/[:\-]|\.\d{3}/g, ''),
        credentialScope,
        hashedCanonicalRequest
    ].join('\n');

    const signatureKey = await getSignatureKey(secretKey, date, service, region);
    const signature = await hmacSha256(stringToSign, signatureKey);

    return `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`;
}

// 上传图片到COS
async function uploadImageToCos(file, env) {
    try {
        // 生成唯一文件名
        const fileExtension = file.name.split('.').pop();
        const fileName = `images/${Date.now()}-${Math.random().toString(36).substring(2, 15)}.${fileExtension}`;
        
        // 准备上传到COS
        const cosUrl = `https://${env.TENCENT_BUCKET}.cos.${env.TENCENT_REGION}.myqcloud.com/${fileName}`;
        
        const cosRequestHeaders = new Headers();
        cosRequestHeaders.set('Host', `${env.TENCENT_BUCKET}.cos.${env.TENCENT_REGION}.myqcloud.com`);
        cosRequestHeaders.set('Content-Type', file.type);
        
        // 读取文件数据
        const fileBuffer = await file.arrayBuffer();
        
        // 创建一个用于签名的临时 Request 对象
        const tempRequestForSigning = new Request(cosUrl, {
            method: 'PUT',
            headers: cosRequestHeaders,
            body: fileBuffer,
        });
        
        // 生成签名
        const authorization = await getCosAuthorization(
            tempRequestForSigning,
            env.TENCENT_SECRET_ID,
            env.TENCENT_SECRET_KEY,
            'cos',
            env.TENCENT_REGION
        );
        cosRequestHeaders.set('Authorization', authorization);
        
        // 发送请求到 COS
        const cosResponse = await fetch(cosUrl, {
            method: 'PUT',
            headers: cosRequestHeaders,
            body: fileBuffer,
        });
        
        if (cosResponse.ok) {
            // 返回COS文件URL
            return {
                success: true,
                url: cosUrl,
                fileName: fileName
            };
        } else {
            const errorBody = await cosResponse.text();
            console.error('COS upload failed:', errorBody);
            return {
                success: false,
                error: 'Failed to upload to COS.',
                details: errorBody
            };
        }
    } catch (error) {
        console.error('COS upload error:', error);
        return {
            success: false,
            error: 'COS upload error: ' + error.message
        };
    }
}

// JSON 响应辅助函数
 

// 处理图片上传
async function handleImageUpload(request, env, userId, corsHeaders) {
    try {
        const formData = await request.formData();
        const file = formData.get('image');
        
        if (!file) {
            return jsonResponse({ error: '未选择图片' }, 400, corsHeaders);
        }

        console.log('Upload request:', {
            userId: userId,
            fileName: file.name,
            fileSize: file.size,
            mimeType: file.type
        });

        // 检查文件类型
        if (!file.type.startsWith('image/')) {
            return jsonResponse({ error: '请上传图片文件' }, 400, corsHeaders);
        }

        // 检查文件大小（限制为5MB）
        if (file.size > 5 * 1024 * 1024) {
            return jsonResponse({ error: '图片大小不能超过5MB' }, 400, corsHeaders);
        }

        // 上传到COS
        const uploadResult = await uploadImageToCos(file, env);
        
        if (!uploadResult.success) {
            return jsonResponse({ error: uploadResult.error }, 500, corsHeaders);
        }
        
        // 保存COS链接到数据库
        const result = await env.DB.prepare(`
            INSERT INTO images (user_id, filename, cos_url, mime_type, file_size, created_at) 
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        `).bind(
            userId,
            file.name,
            uploadResult.url,
            file.type,
            file.size
        ).run();

        console.log('Image uploaded successfully:', {
            imageId: result.meta.last_row_id,
            cosUrl: uploadResult.url,
            success: result.success,
            changes: result.changes
        });

        return jsonResponse({ 
            imageId: result.meta.last_row_id,
            imageUrl: uploadResult.url,
            message: '图片上传成功' 
        }, 200, corsHeaders);

    } catch (error) {
        console.error('Image upload error details:', {
            message: error.message,
            stack: error.stack,
            userId: userId
        });
        return jsonResponse({ error: '图片上传失败: ' + error.message }, 500, corsHeaders);
    }
}

 
// 创建销售记录
async function createSale(request, db, userId, corsHeaders) {
    try {
        const { itemName, quantity, price, buyerName, imageUrl } = await request.json();
        
        console.log('Creating sale:', { itemName, quantity, price, buyerName, imageUrl, userId });
        
        if (!itemName || !quantity || !price) {
            return jsonResponse({ error: '物品名称、数量和单价必填' }, 400, corsHeaders);
        }
        
        // 如果有图片URL，确保它存在于images表中
        if (imageUrl) {
            const imageExists = await db.prepare('SELECT id FROM images WHERE cos_url = ? AND user_id = ?')
                .bind(imageUrl, userId).first();
            
            if (!imageExists) {
                // 如果图片不存在于images表中，添加它
                await db.prepare(`
                    INSERT INTO images (user_id, filename, cos_url, mime_type, file_size, created_at) 
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                `).bind(
                    userId,
                    'unknown.jpg', // 默认文件名
                    imageUrl,
                    'image/jpeg', // 默认MIME类型
                    0 // 默认文件大小
                ).run();
            }
        }
        
        const totalPrice = quantity * price;
        
        // 创建销售记录，使用COS链接
        const result = await db.prepare(`
            INSERT INTO sales (item_name, quantity, price, total_price, user_id, buyer_name, image_url) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(itemName, quantity, price, totalPrice, userId, buyerName || '', imageUrl || null).run();
        
        console.log('Sale created:', result);
        
        return jsonResponse({ id: result.meta.last_row_id, success: true }, 200, corsHeaders);
    } catch (error) {
        console.error('Create sale error:', error);
        return jsonResponse({ error: '创建销售记录失败: ' + error.message }, 500, corsHeaders);
    }
}

// 获取当前用户的销售记录
async function getMySales(db, userId, corsHeaders) {
    const sales = await db.prepare(`
        SELECT s.* 
        FROM sales s
        WHERE s.user_id = ? 
        ORDER BY s.created_at DESC
    `).bind(userId).all();
    
    // 计算用户个人统计
    const stats = await db.prepare(`
        SELECT 
            COUNT(*) as total_sales,
            SUM(quantity) as total_quantity,
            SUM(total_price) as total_revenue,
            COUNT(DISTINCT item_name) as unique_items
        FROM sales 
        WHERE user_id = ?
    `).bind(userId).first();
    
    return jsonResponse({ 
        sales: sales.results || sales,
        stats: {
            total_sales: stats.total_sales || 0,
            total_quantity: stats.total_quantity || 0,
            total_revenue: stats.total_revenue || 0,
            unique_items: stats.unique_items || 0
        }
    }, 200, corsHeaders);
}

// 删除销售记录
async function deleteSale(db, id, userId, corsHeaders) {
    // 检查权限
    const sale = await db.prepare('SELECT user_id FROM sales WHERE id = ?').bind(id).first();
    if (!sale || sale.user_id !== userId) {
        return jsonResponse({ error: '无权限' }, 403, corsHeaders);
    }
    
    await db.prepare('DELETE FROM sales WHERE id = ?').bind(id).run();
    
    return jsonResponse({ success: true }, 200, corsHeaders);
}

// 获取统计数据
async function getStats(db, corsHeaders) {
    // 总体统计
    const stats = await db.prepare(`
        SELECT 
            COUNT(DISTINCT s.id) as total_sales,
            SUM(s.quantity) as total_quantity,
            SUM(s.total_price) as total_revenue,
            COUNT(DISTINCT u.id) as total_users,
            COUNT(DISTINCT s.item_name) as unique_items
        FROM sales s
        JOIN users u ON s.user_id = u.id
    `).first();
    
    // 热门物品
    const topItems = await db.prepare(`
        SELECT 
            item_name,
            SUM(quantity) as total_quantity,
            SUM(total_price) as total_revenue,
            COUNT(*) as sales_count
        FROM sales
        GROUP BY item_name
        ORDER BY total_quantity DESC
        LIMIT 10
    `).all();
    
    // 今日销售
    const todayStats = await db.prepare(`
        SELECT 
            COUNT(*) as today_sales,
            SUM(quantity) as today_quantity,
            SUM(total_price) as today_revenue
        FROM sales
        WHERE DATE(created_at) = DATE('now')
    `).first();
    
    // 物品分类统计
    const categoryStats = await db.prepare(`
        SELECT 
            item_name,
            SUM(quantity) as total_quantity,
            SUM(total_price) as total_revenue,
            COUNT(*) as sales_count,
            AVG(price) as avg_price,
            MIN(price) as min_price,
            MAX(price) as max_price
        FROM sales
        GROUP BY item_name
        ORDER BY total_revenue DESC
    `).all();
    
    return jsonResponse({ 
        stats: {
            total_sales: stats.total_sales || 0,
            total_quantity: stats.total_quantity || 0,
            total_revenue: stats.total_revenue || 0,
            total_users: stats.total_users || 0,
            unique_items: stats.unique_items || 0,
            today_sales: todayStats.today_sales || 0,
            today_quantity: todayStats.today_quantity || 0,
            today_revenue: todayStats.today_revenue || 0
        }, 
        topItems: topItems.results || topItems,
        categoryStats: categoryStats.results || categoryStats
    }, 200, corsHeaders);
}

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS 头
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // 处理 OPTIONS 请求
    if (method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    // 只处理 /api/* 路径
    if (!path.startsWith('/api/')) {
        return new Response('Not Found', { status: 404 });
    }

    try {
        const db = env.DB;
        
        // 用户验证（除了登录和注册）
        let userId = null;
        let username = null;
        if (!path.includes('/login') && !path.includes('/register')) {
            const authHeader = request.headers.get('Authorization');
            if (!authHeader) {
                return jsonResponse({ error: '未授权' }, 401, corsHeaders);
            }
            
            try {
                username = decodeURIComponent(authHeader);
            } catch (e) {
                username = authHeader;
            }
            
            const user = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
            if (!user) {
                return jsonResponse({ error: '用户不存在' }, 401, corsHeaders);
            }
            userId = user.id;
        }

        // 路由处理
        if (path === '/api/register' && method === 'POST') {
            return await handleRegister(request, db, corsHeaders);
        } else if (path === '/api/login' && method === 'POST') {
            return await handleLogin(request, db, corsHeaders);
        } else if (path === '/api/sales' && method === 'POST') {
            return await createSale(request, db, userId, corsHeaders);
        } else if (path === '/api/mysales' && method === 'GET') {
            return await getMySales(db, userId, corsHeaders);
        } else if (path === '/api/stats' && method === 'GET') {
            return await getStats(db, corsHeaders);
        } else if (path.startsWith('/api/sales/') && method === 'DELETE') {
            const id = path.split('/')[3];
            return await deleteSale(db, id, userId, corsHeaders);
        } else if (path === '/api/upload-image' && method === 'POST') {
            return await handleImageUpload(request, env, userId, corsHeaders);
        }

        return jsonResponse({ error: '未找到路由' }, 404, corsHeaders);

    } catch (error) {
        console.error('API Error:', error);
        return jsonResponse({ error: '服务器错误: ' + error.message }, 500, corsHeaders);
    }
}

// JSON 响应辅助函数
function jsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...headers }
    });
}

// 用户注册
async function handleRegister(request, db, corsHeaders) {
    try {
        const { username, password } = await request.json();
        
        if (!username || !password) {
            return jsonResponse({ error: '用户名和密码必填' }, 400, corsHeaders);
        }

        // 检查用户是否存在
        const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        if (existing) {
            return jsonResponse({ error: '用户名已存在' }, 400, corsHeaders);
        }

        // 创建用户
        const result = await db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').bind(username, password).run();
        
        return jsonResponse({ username, userId: result.meta.last_row_id }, 200, corsHeaders);
    } catch (error) {
        console.error('Register error:', error);
        return jsonResponse({ error: '注册失败: ' + error.message }, 500, corsHeaders);
    }
}

// 用户登录
async function handleLogin(request, db, corsHeaders) {
    try {
        const { username, password } = await request.json();
        
        const user = await db.prepare('SELECT id, password_hash FROM users WHERE username = ?').bind(username).first();
        if (!user || user.password_hash !== password) {
            return jsonResponse({ error: '用户名或密码错误' }, 401, corsHeaders);
        }
        
        return jsonResponse({ username, userId: user.id }, 200, corsHeaders);
    } catch (error) {
        console.error('Login error:', error);
        return jsonResponse({ error: '登录失败: ' + error.message }, 500, corsHeaders);
    }
}

// 其他函数保持不变...