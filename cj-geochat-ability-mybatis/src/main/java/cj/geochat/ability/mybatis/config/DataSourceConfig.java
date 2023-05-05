package cj.geochat.ability.mybatis.config;

import cj.geochat.ability.mybatis.DataSourceContext;
import cj.geochat.ability.mybatis.RoutingDataSource;
import com.alibaba.druid.pool.DruidDataSource;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.boot.autoconfigure.MybatisProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.Map;

@Configuration
@AutoConfigureAfter({MybatisProperties.class, ResourceLoader.class})
@EnableConfigurationProperties({MybatisProperties.class})
@ComponentScan(basePackages = {"cj.geochat.ability.mybatis"})
public class DataSourceConfig {

    MybatisProperties mybatisProperties;
    ResourceLoader resourceLoader;

    public DataSourceConfig(MybatisProperties mybatisProperties, ResourceLoader resourceLoader) {
        this.mybatisProperties = mybatisProperties;
        this.resourceLoader = resourceLoader;
    }

    @Primary
    @Bean
    @ConfigurationProperties(prefix = "datasource.write")
    public DataSource writeDataSource() {
        return new DruidDataSource();
    }

    @Bean
    @ConfigurationProperties(prefix = "datasource.read")
    public DataSource readDataSource() {
        return new DruidDataSource();
    }

    //配置数据源
    @Bean
    public AbstractRoutingDataSource routingDataSource() {
        RoutingDataSource proxy = new RoutingDataSource();
        Map<Object, Object> targetDataSources = new HashMap<>(2);
        targetDataSources.put(DataSourceContext.WRITE, writeDataSource());
        targetDataSources.put(DataSourceContext.READ, readDataSource());
        proxy.setDefaultTargetDataSource(writeDataSource());
        proxy.setTargetDataSources(targetDataSources);
        return proxy;
    }

    @Bean
    public DataSourceTransactionManager dataSourceTransactionManager() {
        return new DataSourceTransactionManager(routingDataSource());
    }


    //定义一个注解 任何方法加上该注解 标注为只读方法
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ReadOnly {
    }

    //配置sqlsession工厂 让它走我们自定义的数据源
    @Bean
    public SqlSessionFactory sqlSessionFactory() throws Exception {
        SqlSessionFactoryBean bean = new SqlSessionFactoryBean();
        bean.setDataSource(routingDataSource());
//        ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
//		 实体类对应的位置
        //参数spring的类：MybatisAutoConfiguration实现
        if (StringUtils.hasLength(mybatisProperties.getTypeAliasesPackage())) {
            bean.setTypeAliasesPackage(mybatisProperties.getTypeAliasesPackage());
        }
//		 mybatis的XML的配置
        if (!ObjectUtils.isEmpty(mybatisProperties.resolveMapperLocations())) {
            bean.setMapperLocations(mybatisProperties.resolveMapperLocations());
        }
        //config-location: classpath:/mybatis-config.xml
        if (StringUtils.hasText(this.mybatisProperties.getConfigLocation())) {
            bean.setConfigLocation(this.resourceLoader.getResource(mybatisProperties.getConfigLocation()));
        }
        if (this.mybatisProperties.getConfigurationProperties() != null) {
            bean.setConfigurationProperties(this.mybatisProperties.getConfigurationProperties());
        }
        if (this.mybatisProperties.getTypeAliasesSuperType() != null) {
            bean.setTypeAliasesSuperType(this.mybatisProperties.getTypeAliasesSuperType());
        }

        if (StringUtils.hasLength(this.mybatisProperties.getTypeHandlersPackage())) {
            bean.setTypeHandlersPackage(this.mybatisProperties.getTypeHandlersPackage());
        }
        return bean.getObject();
    }

}

