# 锐捷RG-UAC统一上网行为管理审计系统账号密码信息泄露漏洞
锐捷RG-UAC统一上网行为管理审计系统存在账号密码信息泄露,可以间接获取用户账号密码信息登录后台。

## 使用说明:
python3 RG-UAC_login_poc.py -u http://127.0.0.1:1111 单个url测试

python3 RG-UAC_login_poc.py -f url.txt 批量检测

## 免责声明

由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
