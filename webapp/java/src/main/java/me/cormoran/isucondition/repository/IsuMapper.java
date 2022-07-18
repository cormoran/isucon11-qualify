package me.cormoran.isucondition.repository;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Getter;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.io.InputStream;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.List;

@Mapper
public interface IsuMapper {

    @Getter
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    class Isu {
        Long id;
        String jiaIsuUuid;
        String name;
        byte[] image;
        String character;
        String jiaUserId;
        Timestamp createdAt;
        Timestamp updatedAt;
    }

    @Insert("insert into isu (jia_isu_uuid, name, image, jia_user_id) values (#{jiaIsuUuid}, #{isuName}, #{image}, #{jiaUserId})")
    void insertIsu(String jiaIsuUuid, String isuName, byte[] image, String jiaUserId);

    @Update("update isu set `character` = #{character} where jia_isu_uuid = #{jiaIsuUuid}")
    void updateIsuCharacter(String jiaIsuUuid, String character);

    @Select("select * from isu where jia_user_id = #{jiaUserId} and jia_isu_uuid = #{jiaIsuUuid}")
    Isu getIsu(String jiaUserId, String jiaIsuUuid);

    @Select("select * from isu where jia_user_id = #{jiaUserId} order by id desc")
    List<Isu> getIsuList(String jiaUserId);

    @Select("select * from isu where `character` = #{character}")
    List<Isu> getIsuListByCharacters(String character);

    @Select("select `character` from isu group by `character`")
    List<String> getCharacters();

    @Select("select count(*) from isu where jia_isu_uuid = #{jiaIsuUuid}")
    int countIsu(String jiaIsuUuid);

    @Select("select count(*) from isu where jia_isu_uuid = #{jiaIsuUuid} and jia_user_id = #{jiaUserId}")
    int countIsu2(String jiaIsuUuid, String jiaUserId);
}
