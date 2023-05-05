spring:
  profiles:
    active: dev
  mvc:
    pathmatch:
        #swagger2的bug，只认这种方式，而springboot2.6默认已不是这种匹配模式。否则启动时报错
        #不配的话报：at springfox.documentation.spring.web.WebMvcPatternsRequestConditionWrapper.getPatterns
      matching-strategy: ANT_PATH_MATCHER