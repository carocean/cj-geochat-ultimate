spring:
  data:
    redis:
      mode: sentinel
      password: 123456
      sentinel:
        password: 123456
        master: local-master
        nodes:
          - geochat-ecs.local:26379
          - geochat-ecs.local:26380
          - geochat-ecs.local:26381
      lettuce:
        pool:
          max-active: 8 # Maximum number of connections in connection pool （ Use a negative value to indicate that there is no limit ） Default 8
          max-wait: -1 # Connection pool maximum blocking wait time （ Use a negative value to indicate that there is no limit ） Default -1
          max-idle: 8 # The maximum free connection in the connection pool Default 8
          min-idle: 0 # The smallest free connection in the connection pool Default 0
          enabled: true