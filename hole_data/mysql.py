#! -*- coding=utf8 -*-
import MySQLdb

class Mysql():

    def __init__(self, host, user, passwd, database):
        self.host = host
        self.database = database
        self.user = user
        self.passwd = passwd
        self.conn = None

    def _getConnect(self):
        if self.conn == None:
            try:
                conn = MySQLdb.connect(self.host, self.user, self.passwd, self.database)
            except Exception:
                print "exception hanppend in get connection"
        return conn

    # 插入数据
    def excute_sql(self, sql, *args):
        conn = self._getConnect()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, args)
            conn.commit()
        except:
            # Rollback in case there is any error
            conn.rollback()

    # 读取数据
    def select_sql(self, sql):
        results = None
        conn = self._getConnect()
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
        except Exception as e:
            print e
            # Rollback in case there is any error
            conn.rollback()
        return results

    def close_connection(self):
        conn = self._getConnect()
        conn.close()

if __name__ == "__main__":
    host, user, passwd, database = "127.0.0.1", "root", "jlu52111812", "test1"
    mysql = Mysql(host, user, passwd, database)

    XSS_PATTERNS = (
        (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->","<!--.'.xss.'.--> inside the comment", ""),
        (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>","<script>.'.xss.'.</script>. enclosed by <script> tags. inside single-quotes", ""),
        (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>',"'<script>..xss..</script>'. enclosed by <script> tags. inside double-quotes", ""),
        (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>","<script>.xss.</script> enclosed by <script> tags", ""),
        (r">[^<]*%(chars)s[^<]*(<|\Z)", ">.xss.< outside of tags", r"(?s)<script.+?</script>|<!--.*?-->"),
        (r"<[^>]*'[^>']*%(chars)s[^>']*'[^>]*>", "<.'.xss.'.>.inside the tag. inside single-quotes", r"(?s)<script.+?</script>|<!--.*?-->"),
        (r'<[^>]*"[^>"]*%(chars)s[^>"]*"[^>]*>', "<.'.xss.'.>. inside the tag. inside double-quotes", r"(?s)<script.+?</script>|<!--.*?-->"),
        (r"<[^>]*%(chars)s[^>]*>", "<.xss.> inside the tag. outside of quotes", r"(?s)<script.+?</script>|<!--.*?-->")
    )

    DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response
        "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
        "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
        "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
        "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
        "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
        "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
        "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
        "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
    }

    #创建漏洞库表
    sql = "CREATE TABLE if not exists `holedb` (\
                    `id` int(11) NOT NULL AUTO_INCREMENT,\
                    `type` varchar(255) DEFAULT NULL,\
                    `info` varchar(255) DEFAULT NULL,\
                    `feature` varchar(255) DEFAULT NULL,\
                    `ctime` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,\
                    PRIMARY KEY (`id`)\
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    mysql.excute_sql(sql)

    sql2 = "insert into holedb (type, info, feature) VALUES ( %s, %s, %s )"

    # 添加 xss漏洞特征
    for xss in XSS_PATTERNS:
        key = xss[1]
        value = ",".join(xss)
        mysql.excute_sql(sql2, "xss", key, value)

    # 添加sql注入漏洞特征
    for key in DBMS_ERRORS.keys():
        values = DBMS_ERRORS.get(key)
        for value in values:
            mysql.excute_sql(sql2, "sql", key, value)

    mysql.close_connection()


