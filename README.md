# cj-geochat-ultimate
地微：基台/顶层和能力项目
## 编译
- 环境与版本切换问题
> 由于该工程是基础工程，为其它工程提供能力，因此在此工程中要使用固定的版本号，而不是变量。使用变量作为版本号会导致下游工程引用报错，原因：  
> 下游工程虽然指定的是确定的版本号，但引用的能力工程由于版本号是变量，它无法在能力工程中递归解析变量定义的版本。 
> 因此不要使用maven的环境变量配置来切换版本  
> 方法：  
> 1、安装插件：maven project version  
> 2、在idea右侧的maven视图面板有一向上箭头  
> 3、点击该箭头可以自动修改工程中的所有项目版号  
## 下游工程使用
> 引用release版：cj-geochat-parent  
> 引用snapshot版：cj-geochat-parent-snapshot  
> 注意：不推荐直接引用父项目：cj-geochat-ultimate，原因是：如果引用的是它，则下游工程引用能力时需要手工指定版本号。  
- 例子：
```xml
<parent>
        <groupId>cj.geochat</groupId>
        <artifactId>cj-geochat-parent</artifactId>
        <version>1.5.0</version>
</parent>
```
```xml
<parent>
        <groupId>cj.geochat</groupId>
        <artifactId>cj-geochat-parent-snapshot</artifactId>
        <version>1.5.0-SNAPSHOT</version>
</parent>
```