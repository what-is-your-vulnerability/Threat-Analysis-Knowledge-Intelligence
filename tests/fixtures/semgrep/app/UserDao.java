package app;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserDao {
    public ResultSet find(Connection connection, String name) throws Exception {
        Statement statement = connection.createStatement();
        return statement.executeQuery("SELECT * FROM USERS WHERE NAME = '" + name + "'");
    }
}
