package app;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
public class Caller {
    private final Sender sender;
    private final Pay pay;
    private final AccountMapper accountMapper;
    private final ARepo aRepo;
    private final ItemMapper itemMapper;
    private final Profile profile;
    public Caller(Sender sender, Pay pay, AccountMapper accountMapper, ARepo aRepo, ItemMapper itemMapper, Profile profile) {
        this.sender = sender;
        this.pay = pay;
        this.accountMapper = accountMapper;
        this.aRepo = aRepo;
        this.itemMapper = itemMapper;
        this.profile = profile;
    }
    public void useInterface() { sender.send("x"); }
    public void useAmbiguous() { pay.charge(); }
    public Account useMapper(long accountId) { return accountMapper.findById(accountId); }
    public void useExternal() { Instant now = Instant.now(); now.toString(); }
    public void useMissing() { aRepo.missing(); }
    public void useLocal() { helper(); }
    private void helper() {}
    public List<String> useMethodReference(List<Account> rows) {
        return rows.stream().map(itemMapper::toItem).collect(Collectors.toList());
    }
    public long useRecordAccessor(Account account) { return account.accountId(); }
    public String useLombok() { return profile.getNickname(); }
    public void useVar() { var repo = new ARepo(); repo.save(3); }
    public void useChain() { accountMapper.findById(1).loginId().trim(); }
    public Object useReflection(Method m) throws Exception { return m.invoke(this); }
    public void useUnknownReceiver(List<ARepo> repos) { repos.forEach(r -> r.save(1)); }
    public String useEnum(String v) { Sort sort = Sort.parse(v); return sort.value(); }
    public void useUnknownName(List<String> rows) { rows.forEach(r -> r.strip()); }
}
