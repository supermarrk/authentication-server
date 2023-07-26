package org.pajunmacode.authenticationserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.mongodb.MongoDatabaseFactory;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;
import org.springframework.data.mongodb.core.convert.*;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class MongoConfig { //extends AbstractMongoClientConfiguration {

    @Autowired
    private MongoDatabaseFactory mongoDatabaseFactory;

    @Autowired
    private MongoMappingContext mongoMappingContext;

    @Autowired
    private JwtToUserConverter converter;

    @Autowired
    private UsernamePWAuthTokenConverter usernamePWAuthTokenConverter;

    @Bean
    public MappingMongoConverter mongoConverter() throws Exception {
        DbRefResolver dbRefResolver = new DefaultDbRefResolver(mongoDatabaseFactory);
        MappingMongoConverter mongoConverter = new MappingMongoConverter(dbRefResolver, mongoMappingContext);
        //this is my customization
        mongoConverter.setMapKeyDotReplacement("_");
//        mongoConverter.getCustomConversions().registerConvertersIn();
        mongoConverter.setCustomConversions(customConversions());
        return mongoConverter;
    }

//    @Bean
//    public MongoCustomConversions.MongoConverterConfigurationAdapter mongoConverterConfigurationAdapter() {
//        MongoCustomConversions.MongoConverterConfigurationAdapter adapter = new MongoCustomConversions.MongoConverterConfigurationAdapter();
//        adapter.registerConverter(usernamePWAuthTokenConverter);
//        return adapter;
//    }

//    @Override
//    protected void configureConverters(MongoCustomConversions.MongoConverterConfigurationAdapter adapter) {
//        adapter.registerConverter(new UsernamePWAuthTokenConverter());
//    }

    //    @Bean
    public CustomConversions customConversions() {
        List<Converter<?, ?>> converterList = new ArrayList<Converter<?, ?>>();
//        JwtToUserConverter converter = new JwtToUserConverter();
        converterList.add(converter);
        converterList.add(usernamePWAuthTokenConverter);
        return new CustomConversions(converterList);
    }
}