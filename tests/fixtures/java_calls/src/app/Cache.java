package app;
import java.util.HashMap;
import java.util.Map;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
@Service
public class Cache {
    private static final int LIMIT = 10;
    private static final Map<String, String> SHARED = new HashMap<>();
    private static int counter = 0;
    private final Map<String, String> perTenant = new HashMap<>();
    private String lastUser;
    private final AccountMapper accountMapper;
    public Cache(AccountMapper accountMapper) { this.accountMapper = accountMapper; }
    @Cacheable("accounts")
    public Account load(long id) { return accountMapper.findById(id); }
}
