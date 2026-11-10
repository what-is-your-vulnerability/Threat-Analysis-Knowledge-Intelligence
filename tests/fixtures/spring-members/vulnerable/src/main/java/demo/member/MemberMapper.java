package demo.member;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface MemberMapper {

    record Member(long id, String name, String status) {}

    List<Member> findAll();

    int updateStatus(@Param("id") long id, @Param("status") String status);

    int deleteById(@Param("id") long id);
}
