引用
       <dependency>
            <groupId>cj.geochat</groupId>
            <artifactId>cj-geochat-ability-config</artifactId>
            <type>pom</type>
            <version>0.0.1</version>
        </dependency>

#开发环境
spring:
  cloud:
    config:
      #写死指向配置中心地址
      uri: http://localhost:8861
      #      #通过注册中心自动发现配置中心地址，注意它会获取到docker内的ip这样就会加载错误
      #      discovery: #config配置中心高可用
      #        # 开启 Config 服务发现与注册
      #        enabled: true
      #        # 指定 server
      #        service-id: CJ-geochat-CONFIG-SERVER #注册到Eureka的配置中心微服务名称
      profile: dev
      label: master
  #      username:
  #      password:

#生产环境
spring:
  cloud:
    config:
      #      写死指向配置中心地址
      #      uri: http://localhost:8861
      #通过注册中心自动发现配置中心地址，注意它会获取到docker内的ip这样就会加载错误
      discovery: #config配置中心高可用
        # 开启 Config 服务发现与注册
        enabled: true
        # 指定 server
        #注册到Eureka的配置中心微服务名称
        service-id: cj-geochat-config-server
      profile: prod
      label: master
  #      username:
  #      password: