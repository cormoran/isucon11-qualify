package me.cormoran.isucondition.repository;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface IsuAssociationConfigMapper {
    @Select("select url from isu_association_config where name = #{name}")
    String getJiaServiceUrl(String name);

    @Insert("INSERT INTO `isu_association_config` (`name`, `url`) VALUES (#{name}, #{url}) ON DUPLICATE KEY UPDATE `url` = VALUES(`url`)")
    void insertJiaServiceUrl(String name, String url);
}
