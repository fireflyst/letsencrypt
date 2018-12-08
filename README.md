# letsencrypt

## 简介
该程序包是基于golang.org/x/crypto/acme进行构建的,可以很轻易的实现证书申请TLS证书

git clone https://github.com/nathan-osman/go-simpleacme 代码 修复了http证书申请流程, 添加了dns-txt认证方式

##用法示例

### dns-txt认证方式

    domains := []string{"example.com", "www.example.com"}
    path := domains[0]
    ctx := context.Background()
    _, err := os.Stat(path)
    if err != nil {
      err = os.Mkdir(path, 644)
      if err != nil {
        fmt.Println(0, err)
      }
    }

    c, err := acme.New(ctx, "account.key", "test@aaa.com", path)
    if err != nil {
      fmt.Println(1, err)
    }

// http change
    err = c.Create(ctx,  "test.key", "test.crt", ":http", path, domains...)
    if err != nil {
      fmt.Println(2, err)
    }
    
### http认证方式

// dns change
  err = c.Create(ctx,  "test.key", "test.crt", ":dns", domain, domains...)
    if err != nil {
      fmt.Println(2, err)
    }
    
完成！如果一切顺利，您现在将在新建一个目录下该目录下面三个新文件：

你的域名名字的目录 

 - account.key 帐户密钥，可以重复使用
 - test.key 证书的私钥
 - test.crt 域名的证书包
 
 http挑战需要把输出的文件放到相应域名能访问的相应位置
 dns-txt挑战需根据输出给出添加相应的dns-txt解析
  
