## 配置 swagger.yml
```yaml
appdoc:
  info:
    title: 测试OutsideApp
    description: 可放到网关外部的应用
    summary:
    version: 1.0.0
    contact:
      name: cj 18023457655
      email: zhaoxiangbin_2005@126.com
      url:
    license:
      name:
      identifier:
      url:
  token:
    #名称则被作为in所指的集合的属性名，Authorization是spring权限框架标准认证头。也可定自定义名称，但：
    #如果scheme是bearer且type是http，in是header则不论name设置为什么名称，swagger-ui均解释为Authorization
    #而knife4j会严格按照配置解析。因此要配成一致。
    name: Authorization
    #如果是内应用直接使用swagger的api，则使用inside_app_token固定的头格式。注意使用内应用api认证需配置type：apiKey且scheme为空
    #    name: inside_app_token
    #取值：http|apiKey
    #http类型则scheme应用bearer，如果不配bearer在swagger-ui界面认证弹窗中无法使用。
    #apiKey用于自定义认证，它将name作为在in中的参数名，注意：如果使用apiKey则scheme不起作用
    type: http
    #取值：cookie|header|query
    in: header
    #取值：basic|bearer|digest
    #这里配置 bearer 后，你的请求里会自动在 token 前加上 Bearer
    #如果scheme指定为bearer则swagger会默认为请求头Authorization格式，即：Authorization:Bearer xxx
    #因此scheme不能随意指定值，需在Authorization协议支持的范围，因此name如果非Authorization则schema无效
    scheme: bearer
  externalDocs:
    description:
    url:
springdoc:
  api-docs:
    enabled: true
  swagger-ui:
    enabled: true
    #浏览器关闭是否保持认证的数据
    persist-authorization: false
  #有几个版本的api则在此配置几个组
  group-configs:
    - group: all-api
      paths-to-match:
        - /api/v1/**
        - /api/v2/**
    - group: v1-api
      paths-to-match:
        - /api/v1/**
    - group: v2-api
      paths-to-match:
        - /api/v2/**
#    disable-swagger-default-url: true
# knife4j的增强配置，不需要增强可以不配
# https://doc.xiaominfo.com/docs/quick-start
knife4j:
  enable: true
  setting:
    language: zh_cn
```