package cj.geochat.ability.mybatis;

import cj.geochat.ability.mybatis.config.DataSourceConfig;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class ReadOnlyInterceptor implements Ordered {

    //切入的条件 标注该注解的方法 （只能标注在service层）
    @Around("@annotation(readOnly)")
    public Object setRead(ProceedingJoinPoint joinPoint, DataSourceConfig.ReadOnly readOnly) throws Throwable {
        try {
            DataSourceContext.setDbType(DataSourceContext.READ);
            return joinPoint.proceed();
        } finally {
            //清楚DbType一方面为了避免内存泄漏，更重要的是避免对后续在本线程上执行的操作产生影响
            DataSourceContext.clearDbType();
            log.info("清除threadLocal");
        }
    }

    @Override
    public int getOrder() {
        return 0;
    }

}

