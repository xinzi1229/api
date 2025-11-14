// 全局变量
let currentUserId = null;
let currentUsername = null;
let uploadedImageUrl = null;
let isImageUploading = false;
const rootUrl = 'https://yimai.aicoat.top'; // 项目根路径
// 切换登录/注册表单
function toggleAuth() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    loginForm.classList.toggle('hidden');
    registerForm.classList.toggle('hidden');
}

// 登录
async function login(event) {
    event.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch(rootUrl+'/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            localStorage.setItem('username', data.username);
            localStorage.setItem('userId', data.userId);
            currentUsername = data.username;
            currentUserId = data.userId;
            showMainContent();
            showToast('登录成功！');
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        showToast('登录失败', 'error');
    }
}

// 注册
async function register(event) {
    event.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;

    try {
        const response = await fetch(rootUrl+'/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            localStorage.setItem('username', data.username);
            localStorage.setItem('userId', data.userId);
            currentUsername = data.username;
            currentUserId = data.userId;
            showMainContent();
            showToast('注册成功！');
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        showToast('注册失败', 'error');
    }
}

// 显示主内容
function showMainContent() {
    document.getElementById('authSection').classList.add('hidden');
    document.getElementById('mainContent').classList.remove('hidden');
    showSection('record');
}

// 退出登录
function logout() {
    localStorage.removeItem('username');
    localStorage.removeItem('userId');
    location.reload();
}

// 切换页面部分
function showSection(section) {
    const recordSection = document.getElementById('recordSection');
    const profileSection = document.getElementById('profileSection');
    const statsSection = document.getElementById('statsSection');
    
    // 隐藏所有部分
    recordSection.classList.add('hidden');
    profileSection.classList.add('hidden');
    statsSection.classList.add('hidden');
    
    // 显示选中的部分
    if (section === 'record') {
        recordSection.classList.remove('hidden');
        // 更新当前用户名显示
        document.getElementById('currentUsername').textContent = currentUsername;
    } else if (section === 'profile') {
        profileSection.classList.remove('hidden');
        loadMyProfile();
    } else if (section === 'stats') {
        statsSection.classList.remove('hidden');
        loadStats();
    }
}

// 计算总金额
function calculateTotal() {
    const quantity = parseFloat(document.getElementById('itemQuantity').value) || 0;
    const price = parseFloat(document.getElementById('itemPrice').value) || 0;
    const total = quantity * price;
    document.getElementById('totalAmount').textContent = '¥' + total.toFixed(2);
}

// 处理图片选择
async function handleImageSelect(event) {
    const file = event.target.files[0];
    if (!file) return;

    // 检查文件类型
    if (!file.type.startsWith('image/')) {
        showToast('请选择图片文件', 'error');
        return;
    }

    // 检查文件大小
    if (file.size > 5 * 1024 * 1024) {
        showToast('图片大小不能超过5MB', 'error');
        return;
    }

    // 显示预览
    const reader = new FileReader();
    reader.onload = function(e) {
        const preview = document.getElementById('imagePreview');
        preview.src = e.target.result;
        preview.classList.remove('hidden');
    };
    reader.readAsDataURL(file);

    // 上传图片到COS
    await uploadImage(file);
}

// 上传图片到COS
async function uploadImage(file) {
    const formData = new FormData();
    formData.append('image', file);
    
    // 显示上传中状态
    isImageUploading = true;
    document.getElementById('uploadingOverlay').classList.remove('hidden');
    document.getElementById('submitBtn').disabled = true;
    document.getElementById('submitBtn').classList.add('opacity-50', 'cursor-not-allowed');

    try {
        const response = await fetch(rootUrl+'/api/upload-image', {
            method: 'POST',
            headers: {
                'Authorization': encodeURIComponent(currentUsername)
            },
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            uploadedImageUrl = data.imageUrl;
            showToast('图片上传成功');
        } else {
            showToast(data.error, 'error');
            uploadedImageUrl = null;
        }
    } catch (error) {
        showToast('图片上传失败', 'error');
        uploadedImageUrl = null;
    } finally {
        // 隐藏上传中状态
        isImageUploading = false;
        document.getElementById('uploadingOverlay').classList.add('hidden');
        document.getElementById('submitBtn').disabled = false;
        document.getElementById('submitBtn').classList.remove('opacity-50', 'cursor-not-allowed');
    }
}

// 添加销售记录
async function addSale(event) {
    event.preventDefault();
    
    // 检查图片是否正在上传
    if (isImageUploading) {
        showToast('图片正在上传中，请稍候...', 'error');
        return;
    }
    
    const itemName = document.getElementById('itemName').value;
    const quantity = parseInt(document.getElementById('itemQuantity').value);
    const price = parseFloat(document.getElementById('itemPrice').value);
    const buyerName = document.getElementById('buyerName').value;

    try {
        const response = await fetch(rootUrl+'/api/sales', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': encodeURIComponent(currentUsername)
            },
            body: JSON.stringify({ 
                itemName, 
                quantity, 
                price, 
                buyerName,
                imageUrl: uploadedImageUrl 
            })
        });

        const data = await response.json();
        if (response.ok) {
            // 清空表单
            document.getElementById('itemName').value = '';
            document.getElementById('itemQuantity').value = '1'; // 重置为默认值1
            document.getElementById('itemPrice').value = '';
            document.getElementById('buyerName').value = '';
            document.getElementById('imagePreview').classList.add('hidden');
            document.getElementById('imageInput').value = '';
            calculateTotal();
            
            uploadedImageUrl = null;
            showToast('义卖记录添加成功！');
        } else {
            showToast(data.error || '添加失败', 'error');
        }
    } catch (error) {
        console.error('Add sale error:', error);
        showToast('添加失败: ' + error.message, 'error');
    }
}

// 加载用户中心数据
async function loadMyProfile() {
    try {
        // 显示用户名
        document.getElementById('profileUsername').textContent = currentUsername;
        
        // 获取用户销售记录和统计
        const response = await fetch(rootUrl+'/api/mysales', {
            headers: { 'Authorization': encodeURIComponent(currentUsername) }
        });
        const data = await response.json();
        
        // 显示统计数据
        document.getElementById('myTotalSales').textContent = data.stats.total_sales || 0;
        document.getElementById('myTotalQuantity').textContent = data.stats.total_quantity || 0;
        document.getElementById('myTotalRevenue').textContent = '¥' + (data.stats.total_revenue || 0).toFixed(2);
        document.getElementById('myUniqueItems').textContent = data.stats.unique_items || 0;
        
        // 显示销售记录 - 修改为使用COS链接
        const mySalesList = document.getElementById('mySalesList');
        if (data.sales.length === 0) {
            mySalesList.innerHTML = '<tr><td colspan="8" class="px-2 sm:px-4 py-8 text-center text-gray-500">暂无义卖记录</td></tr>';
        } else {
            mySalesList.innerHTML = data.sales.map(sale => `
                <tr class="hover:bg-gray-50">
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm">
                        ${sale.image_url ? 
                            `<img src="${sale.image_url}?imageMogr2/thumbnail/50x50/gravity/Center/crop/50x50" class="image-thumbnail" alt="物品图片" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNTAiIGhlaWdodD0iNTAiIHZpZXdCb3g9IjAgMCA1MCA1MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0yNSAyMEMzMy4yODQzIDIwIDQwIDI2LjcxNTcgNDAgMzVDMzAgNDMuMjg0MyAzMy4yODQzIDQ3IDI1IDQ3QzE2LjcxNTcgNDcgMjAgNDMuMjg0MyAyMCAzNUMyMCAyNi43MTU3IDI2LjcxNTcgMjAgMjUgMjBaIiBmaWxsPSIjOUNBM0FGIi8+CjxwYXRoIGQ9Ik0yNSAyM0MzMS42NTY5IDIzIDM3IDI2LjM0MzEgMzcgMzBDMzcgMzMuNjU2OSAzMS42NTY5IDM3IDI1IDM3QzE4LjM0MzEgMzcgMTMgMzMuNjU2OSAxMyAzMEMxMyAyNi4zNDMxIDE4LjM0MzEgMjMgMjUgMjNaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K'"> ` : 
                            '<span class="text-gray-400">无图片</span>'
                        }
                    </td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                        ${new Date(sale.created_at).toLocaleString('zh-CN')}
                    </td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm font-medium text-gray-900">${sale.item_name}</td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm text-gray-900">${sale.quantity}</td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm text-gray-900">¥${sale.price.toFixed(2)}</td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm font-semibold text-pink-500">¥${sale.total_price.toFixed(2)}</td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm text-gray-900">${sale.buyer_name || '-'}</td>
                    <td class="px-2 sm:px-4 py-3 whitespace-nowrap text-xs sm:text-sm">
                        <button onclick="deleteSale(${sale.id})" class="text-red-600 hover:text-red-900">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        }
    } catch (error) {
        showToast('加载用户数据失败', 'error');
    }
}

// 删除销售记录
async function deleteSale(id) {
    if (!confirm('确定要删除这条义卖记录吗？')) return;

    try {
        const response = await fetch(`/api/sales/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': encodeURIComponent(currentUsername) }
        });

        if (response.ok) {
            // 刷新用户中心数据
            const profileSection = document.getElementById('profileSection');
            if (!profileSection.classList.contains('hidden')) {
                loadMyProfile();
            }
            
            showToast('删除成功！');
        } else {
            const data = await response.json();
            showToast(data.error, 'error');
        }
    } catch (error) {
        showToast('删除失败', 'error');
    }
}

// 加载统计数据
async function loadStats() {
    try {
        const response = await fetch(rootUrl+'/api/stats', {
            headers: { 'Authorization': encodeURIComponent(currentUsername) }
        });
        const data = await response.json();
        
        // 总体统计
        document.getElementById('totalSales').textContent = data.stats.total_sales || 0;
        document.getElementById('totalQuantity').textContent = data.stats.total_quantity || 0;
        document.getElementById('totalRevenue').textContent = '¥' + (data.stats.total_revenue || 0).toFixed(2);
        document.getElementById('uniqueItems').textContent = data.stats.unique_items || 0;
        
        // 今日统计
        document.getElementById('todaySales').textContent = data.stats.today_sales || 0;
        document.getElementById('todayQuantity').textContent = data.stats.today_quantity || 0;
        document.getElementById('todayRevenue').textContent = '¥' + (data.stats.today_revenue || 0).toFixed(2);
        
        // 物品分类统计
        const categoryStatsList = document.getElementById('categoryStatsList');
        if (data.categoryStats && data.categoryStats.length > 0) {
            categoryStatsList.innerHTML = data.categoryStats.map((item, index) => `
                <tr class="category-row">
                    <td class="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                            ${item.item_name}
                        </span>
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                        <span class="text-lg font-semibold">${item.total_quantity || 0}</span>
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                        <span class="text-lg font-bold text-green-600">¥${(item.total_revenue || 0).toFixed(2)}</span>
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                            ${item.sales_count || 0}次
                        </span>
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                        ¥${(item.avg_price || 0).toFixed(2)}
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                        ¥${(item.min_price || 0).toFixed(2)} - ¥${(item.max_price || 0).toFixed(2)}
                    </td>
                </tr>
            `).join('');
        } else {
            categoryStatsList.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-gray-500">暂无数据</td></tr>';
        }
        
        // 热门物品
        const topItems = document.getElementById('topItems');
        topItems.innerHTML = data.topItems.map((item, index) => `
            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition">
                <div class="flex items-center">
                    <span class="text-xl sm:text-2xl font-bold text-gray-400 mr-3 sm:mr-4">#${index + 1}</span>
                    <div>
                        <p class="font-semibold text-gray-800 text-sm sm:text-base">${item.item_name}</p>
                        <p class="text-xs sm:text-sm text-gray-500">销量: ${item.total_quantity} | 笔数: ${item.sales_count}</p>
                    </div>
                </div>
                <span class="text-base sm:text-lg font-bold text-green-500">¥${item.total_revenue.toFixed(2)}</span>
            </div>
        `).join('');
    } catch (error) {
        showToast('加载统计失败', 'error');
    }
}

// 显示提示
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    
    toastMessage.textContent = message;
    toast.firstElementChild.className = type === 'error' ? 
        'bg-red-500 text-white px-4 sm:px-6 py-3 rounded-lg shadow-lg flex items-center' :
        'bg-green-500 text-white px-4 sm:px-6 py-3 rounded-lg shadow-lg flex items-center';
    
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

// 监听输入变化
document.addEventListener('DOMContentLoaded', function() {
    const quantityInput = document.getElementById('itemQuantity');
    const priceInput = document.getElementById('itemPrice');
    
    if (quantityInput) quantityInput.addEventListener('input', calculateTotal);
    if (priceInput) priceInput.addEventListener('input', calculateTotal);
});

// 页面加载时检查登录状态
window.onload = function() {
    const username = localStorage.getItem('username');
    const userId = localStorage.getItem('userId');
    
    if (username && userId) {
        currentUsername = username;
        currentUserId = userId;
        showMainContent();
    }
};
