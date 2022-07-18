package me.cormoran.isucondition.repository;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Insert("insert ignore into user (jia_user_id) values (#{jiaUserId})")
    void insertUser(String jiaUserId);

    @Select("select count(*) from user where jia_user_id = #{jiaUserId}")
    int countUser(String jiaUserId);
}
