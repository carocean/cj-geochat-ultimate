package cj.geochat.ability.mybatis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

@Slf4j
public class RoutingDataSource extends AbstractRoutingDataSource {


    @Override
    protected Object determineCurrentLookupKey() {
        String typeKey = DataSourceContext.getDbType();
        if (typeKey == DataSourceContext.WRITE) {
            log.info("使用了写库");
            return typeKey;
        }
        log.info("使用了读库:{}", DataSourceContext.READ);
        return DataSourceContext.READ;
    }

}

