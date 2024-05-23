# 云端可干扰的抗丢秘密解决方案

## 一.秘密分解方案

### 1.head 和 body 的拆分

秘密和大随机数做异或得到 body, 大随机数做为 head, 即

- head: 随机数
- body: 秘密和随机异或之后的结果

将 head 上传  

  
### 2.body 拆分成 shadow

将 body 做门限共享秘密算法，拆分成 n 份 shadow(shadow-1, shadow-2, shadow-3, .... shadow-n)，设置 k 份可以恢复（n >= k）


## 二.秘密恢复方案

### 1. body 恢复

用 k shadow 做逆门限共享密码算法恢复出 body


### 2.秘密恢复

从云端拉取 head, 将 head 和 body 做逆异或算法得到秘密

