package demo.signup;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SignupMapper {

    int insertMember(@Param("name") String name);

    int markVerified(@Param("verificationId") String verificationId);
}
