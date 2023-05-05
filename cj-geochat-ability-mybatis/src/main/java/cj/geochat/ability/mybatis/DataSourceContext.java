package cj.geochat.ability.mybatis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class DataSourceContext {


    public static final String WRITE = "write";
    public static final String READ = "read";

    //	 将ThreadLocal设置为静态的，可以让当前线程中所有的类都能够共享
    private static ThreadLocal<String> dataSourcePool = new ThreadLocal<>();

    public static void setDbType(String dbType) {

        if (dbType == null) {
            log.error("dbType为空");
            throw new NullPointerException();
        }

        log.info("设置dbType为：{}", dbType);
        dataSourcePool.set(dbType);
    }

    public static String getDbType() {
        return dataSourcePool.get() == null ? WRITE : dataSourcePool.get();
    }

    public static void clearDbType() {
        dataSourcePool.remove();
    }

}

