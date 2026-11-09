package app;
import org.apache.ibatis.annotations.Mapper;
@Mapper
public interface AccountMapper {
    Account findById(long accountId);
}
