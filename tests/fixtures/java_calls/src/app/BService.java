package app;
public class BService {
    private BRepo repo;
    public void run() { repo.save(1); }
    public void runTwo() { this.repo.save(1, 2); }
}
