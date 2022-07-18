package me.cormoran.isucondition.repository;

import lombok.Getter;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.sql.Timestamp;
import java.util.List;

@Mapper
public interface IsuConditionMapper {
    @Getter
    class IsuCondition {
        Long id;
        String jiaIsuUuid;
        Timestamp timestamp;
        Boolean isSitting;
        String condition;
        String message;
        Timestamp createdAt;
    }

    @Select("select * from isu_condition where jia_isu_uuid = #{jiaIsuUuid} order by timestamp desc limit 1")
    IsuCondition getIsuCondition(String jiaIsuUuid);

    @Select("select * from isu_condition where jia_isu_uuid = #{jiaIsuUuid} order by timestamp desc")
    List<IsuCondition> getIsuConditions(String jiaIsuUuid);

    @Select("select * from isu_condition where jia_isu_uuid = #{jiaIsuUuid} order by timestamp asc")
    List<IsuCondition> getIsuConditionsByAsc(String jiaIsuUuid);

    @Select("select * from isu_condition where jia_isu_uuid = #{jiaIsuUuid} and timestamp < #{end} and #{start} <= timestamp order by timestamp desc")
    List<IsuCondition> getIsuConditionWithRange(String jiaIsuUuid, Timestamp start, Timestamp end);

    @Select("select * from isu_condition where jia_isu_uuid = #{jiaIsuUuid} and timestamp < #{end} order by timestamp desc")
    List<IsuCondition> getIsuConditionWithEnd(String jiaIsuUuid, Timestamp end);

    @Insert("insert into isu_condition (jia_isu_uuid, timestamp, is_sitting, condition, message) values (#{jiaIsuUuid}, #{timestamp}, #{isSitting}, #{condition}, #{message})")
    void insertCondition(String jiaIsuUuid, Timestamp timestamp, boolean isSitting, String condition, String message);
}
