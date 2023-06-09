# oauth2 自定流程

地微WEB平台授权、地微移动端授权、三方（网页或移动端）接入授权统一规范

## 一、关键地址

参考：
> https://blog.csdn.net/qq_33036061/article/details/107076918  
> https://blog.csdn.net/nineya_com/article/details/129416660

* /oauth/authorize:      专用于授权码模式。两个功能：

> 1、发放授权码（需先登录）；  
> 2、检测是否需要用户授权并重定向到授权页然后处理用户向其提交的授权页确认结果。  
> 注意：申请授权码的客户端如果开启了用户授权确认，oauth2会发起重定向请求/oauth/confirm_access，因此可拦截此请求返回协议形式，让客户端自定用户确认页面

* /oauth/token:          获取access_token和refresh_token

> （无论是通过授权码或自定义授权模式都要调此接口以换取或获取令牌）

* /oauth/confirm_access: 用户授权页

> 会由auth2自动向客户端发起重定向到此页，认证服务器可拦截此请求重定向到自定义的用户授权页

* /oauth/error:          认证失败
* /oauth/check_token:    资源服务器用来校验token
* /oauth/token_key:      如果jwt模式则可以用此来从认证服务器获取公钥

## 二、流程概要

- 用户通过网关向后台geochat-app（oauth2类型的微服务）发起请求，判断令牌是否合法
- 如果不合法则协议告知客户端需登录（响应中应包含登录地址。根据客户端是否web或移动端，是否是第三方web或第三方移动端）
- 客户端登录：

> 1、如果是Web平台则由客户端重定向到认证中心的登录页  
> 2、如果是移动端则由客户端调起移动端登录页（如果是客户端是第三方的移动端，
> 则根据android或ios的跨app调起规范uri唤起地微app登录，如果是地微app本身的登录，则跳转到登录页)  
> 3、登录后协议告知客户端认证结果  
> 4、如果认证成功，则由客户端根据授权类型向认证服务器发起相应的请求，包括：  
> 4.1、如果是授权码模式，则向/oauth/authorize地址发起请求。
> 4.1.1 如果客户端配置的不需要用户授权确认，
> 则该次请求会由oauth2根据客户端配置的redirect_uri重定向到redirect_uri并在地址附上code值。  
> 4.1.2 如果客户端需要用户授权确认，则该次请求会由oauth2发起重定向到/oauth/confirm_access，
> 服务器端可拦截此请求协议告知客户端用户授权确认的地址，由客户端来跳转到对应的地微平台自定义的用户授权页地址，
> 不在服务器上直接重定向到目标地址是因为，移动端和web端的用户授权页面的跳转规则不同，一样存在
> web或移动端，是否是第三方web或第三方移动端。  
> 4.1.3 自定义的授权页由用户提交到/oauth/authorize，提交后oauth2会向客户端发起重定向到客户端的redirect_uri并附上code值  
> 4.2 如果是非授权码模式，则可直接向/oauth/token获取令牌，并协议告知客户端令牌  
> 4.3 如果已得到授权码，则可向/oauth/token换取令牌，并协议告知客户端令牌

## 注意事项

-
客户端发起请求实际上是指通过像web的ajax、dart的dio、java的httpclient等工具，这些工具均会持有jsessionid，因此只要登录过，则其内任何向/oauth/authorize索要授权码的请求，都不会被重定向到登录，除非这些工具不是同一实例或没有附上jsessionid或会话过期
- 短信验证码、租户认证、邮箱验证码等自定义的认证模式，在登录之后也可像授权码认证模式一样通过向/oauth/authorize提交请求以获取验证码，以此来使用用户授权确认页，不必非得直接向/oauth/token获取令牌。
- 保留对租户认证方式的支持，并让geochat-app支持两种AppAuthentication（对应两种DefaultAppPrincipal），一种是默认的不含租户，一种是租户应用验证器
- 正确理解重定向的概念。

> 重定向是服务器向前端（像web的ajax、dart的dio、java的httpclient等工具）发起重定向响应，根据http协议
> 前端自动发起向重定向地址的请求，实际上是向服务器发起请求并得到重定向地址的响应结果。往往在思想时会误以为服务器直接向另一服务器发起重定向请求，因此要特别注意。

- 简化模式的问题

> 简化模式主要是提供给前端使用的,由前端接收token，如果非要后端接收token，则问题如下：  
>
oauth2的简化发起的重定向地址格式是：http://localhost:11000/api/v1/app/entrypoint#access_token=01h0ejwxpaqytm8hwmpctzqktb&token_type=bearer&state=0239029302939&expires_in=42059  
> 地址查询串部分不是以？分隔，而是以#，遇到#浏览器会当成定位符，如果此地址是后端地址，则前端httpclient等会处理掉#后再自动向后端发起请求，因此
> 后端收不到#号后的查询串。由于此间是oauth2的内部重定向机制，因此无法控制中间环节，应遵循规范，简化模式仅供前端直接获取token使用。

- resource_ids的作用

> 客户端加入的resource_ids类似于资源白名单，如果该白名单非空，则生效，且不在白名单的资源一律禁止访问。  
> 所以要不进行资源控制，客户端资源一定要设为空。  
> 资源一般为微服务名，地微平台在geochat-app中进行资源的访问控制，一个geochat-app就是一个资源，
> 因此geochat-app可以拒止那些设有资源的客户端且不包括这个geochat-app资源的。  
> 用处不是很大，在网关中采用地滤机制来控制更为方便，如：ICheckPermission可以根据角色及访问地址过行有效控制

## 三、功能

- 认证模式支持：

> 1、授权码模式  
> 2、短信验证码模式  
> 3、三方登录模式（微信、支付宝）  
> 4、二维码模式  
> 5、邮箱验证码模式  
> 6、设备确认模式  
> 7、设备验证码模式  
> 8、租户认证模式

- 充许扩展用户
- 充许扩展客户端
- 一个完整的认证流程

> 登录开始  
> ->认证中心校验账户及密码  
> ->协议响应给前端  
> ->前端请求授权码（/oauth/authorize）  
> ->认证中心向前端发起重定向到用户授权确认地址（/oauth/confirm_access）  
> ->前端自动发起请求：用户授权确认  
> ->认证服务器协议响应用户授权请求  
> ->前端提交用户授权请求  
> ->认证服务器重定向到客户端配置的redirect_uri并附上授权码响应给前端  
> ->前端以授权码换取令牌/oauth/token  
> ->前端得到令牌，登录成功  
> ->前端以access_token发起租户认证请求（/oauth/token）  
> ->前端得到租户令牌  
> ->登录完毕

- 一个完整(简化的流程可以不用授权码）的使用短信验证码模式认证的流程

> 请客户端后台请求验证码  
> 客户端后台通过第三方验证码平台收到验证码  
> 用户手机收到短信，登录开始  
> ->认证服务器比对账号及验证码  
> ->协议响应到前端  
> ->前端请求授权码（/oauth/authorize）  
> ->认证中心向前端发起重定向到用户授权确认地址（/oauth/confirm_access）  
> ->前端自动发起请求：用户授权确认  
> ->认证服务器协议响应用户授权请求  
> ->前端提交用户授权请求  
> ->认证服务器重定向到客户端配置的redirect_uri并附上授权码响应给前端  
> ->前端以授权码换取令牌/oauth/token  
> ->前端得到令牌，登录成功

- 一个完整的第三方移动端使用地微登录流程

> 使用安卓和ios的app调起地址规范将地微app调起，该地址包含地微app的登录页面地址  
> 地微登录  
> 返回code给调用方app  
> 调用方向自己的后台申请token  
> 后台再以code向认证中心换取令牌  
> 完成

- 一个完整的小程序获取地微用户信息流程

> 前提是小程序运行在地微app或地微平台中，即运行在宿主中  
> 向/oauth/authorize申请授权码（为了不又回到登录窗，需将宿主的会话id与该请求绑定）  
> 如果是第一次则请求用户授权确认/oauth/confirm_access  
> 用户确认后返回授权码  
> 以授权码换取token  
> 然后小程序可通过网关访问用户信息接口了（根据Scope=userinfo来鉴权）  
> 完成

## 四、用法及参数

参见postman账户下的oauth测试脚本。

- /login

> 登录的最少参数与实现的认证类要求的参数一致，比如用户密码登录，只需要提供用户名、密码即可。

- /oauth/authorize
- 必选参数

> client_id  
> response_type

- 可选参数

> scope 该参数可能有多个，调用者在请求授权时可指定一个子集  
> redirect_uri 该参数可能有多个，用户者在请求授权时要么不选此参数，要么在其中选定一个要跳转的地址。

- 用户授权确认 post /oauth/authorize

> user_oauth_approval：必选，用户授权同意或者拒绝 true/false  
> scope.all：可选，上一步的scope确认 true

- 隐式模式 /oauth/authorize

> 与授权码模式区别：都是先登录；  
> 区别只是在第二步：授权码请求的是response_type=code而隐式直接请求令牌response_type=token。
> 第三步用户授权确认的区别是请求code的返回code，请求token返回token