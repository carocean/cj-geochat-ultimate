# 调用者feign只认spring.application.name，不认eureka.instance.appname配置应用名
# feign则必须命名一个实例名
# 故而不论是服务提供端，还是feign服务消费端，spring.application.name和eureka.instance.appname都指定即可
# feign调用方大小写不区分，而注册中心永远显示为大写