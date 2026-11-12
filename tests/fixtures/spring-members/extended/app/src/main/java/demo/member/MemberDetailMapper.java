package demo.member;

import java.util.Map;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface MemberDetailMapper {

    Map<String, Object> findById(@Param("id") long id);
}
