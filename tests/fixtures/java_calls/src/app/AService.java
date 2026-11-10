package app;
public class AService {
    private final ARepo repo;
    public AService(ARepo repo) { this.repo = repo; }
    public void run() { repo.save(1); }
}
