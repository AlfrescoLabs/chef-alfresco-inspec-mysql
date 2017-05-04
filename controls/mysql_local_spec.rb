user = node.content['db']['root_user']
pass = node.content['db']['server_root_password']
service_name = node.content['mysql_local']['service_name']

# hardening following https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.0.0.pdf

data_dir_attribute = node.content['mysql_local']['datadir']
log_bin = node.content['mysql_local']['my_cnf']['mysqld']['log-bin']

control 'Mysql-Service' do
  impact 1.0
  desc 'mysql service should be enabled and running'

  describe service("mysql-#{service_name}") do
    it { should be_enabled }
    it { should be_running }
  end
end

control 'MySQL Operating System Level Configuration' do
  impact 0.7
  desc ' It is generally accepted that host operating systems should include different filesystem \
  partitions for different purposes.  One set of filesystems are typically called "system \
  partitions", and are generally reserved for host system/application operation.  The other \
  set of filesystems are typically called "non-system partitions", and such locations are \
  generally reserved for storing data \
  Rationale: \
  Moving the database off the system partition will reduce the probability of denial of service \
  via the exhaustion of available disk space to the operating system.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"show variables where variable_name = 'datadir'\" | grep datadir | awk '{print $2}'") do
    its(:stdout) { should_not match(%r{\/^\/$}) } # datadir should not be in root '/'
    its(:stdout) { should_not match(%r{^\/(var|user)\/}) } # datadir should not be in a system directory '/'
    its(:stdout) { should match(data_dir_attribute) }
    its(:exit_status) { should eq 0 }
  end
end

control 'Disabled MySQL Command History' do
  impact 0.7
  desc 'On Linux/UNIX, the MySQL client logs statements executed interactively to a history \
  file.  By default, this file is named .mysql_history in the user\'s home directory. Most \
  interactive commands run in the MySQL client application are saved to a history file.  The \
  MySQL command history should be disabled. \
  Rationale: \
  Disabling the MySQL command history reduces the probability of exposing sensitive \
  information, such as passwords and encryption keys.'

  describe file('/root/.mysql_history') do
    it { should be_symlink }
    it { should exist }
    it { should be_linked_to '/dev/null' }
  end
end

control 'Verify That the MYSQL_PWD Environment Variables Is Not In Use' do
  impact 0.7
  desc 'MySQL can read a default database password from an environment variable called  \
  MYSQL_PWD.  \
  Rationale:  \
  The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL  \
  credentials. Avoiding this may increase assurance that the confidentiality of MySQL  \
  credentials is preserved.'

  describe command('grep MYSQL_PWD /proc/*/environ') do
    its(:stdout) { should_not match 'MYSQL_PWD' }
    its(:stderr) { should eq '' }
    its(:exit_status) { should eq 0 }
  end
end

control 'Disable Interactive Login' do
  impact 0.7
  desc 'When created, the MySQL user may have interactive access to the operating system, which
  means that the MySQL user could login to the host as any other user would.
  Rationale:
  Preventing the MySQL user from logging in interactively may reduce the impact of a
  compromised MySQL account.  There is also more accountability as accessing the operating
  system where the MySQL server lies will require the user\'s own account.  Interactive access
  by the MySQL user is unnecessary and should be disabled'

  describe command('getent passwd mysql | egrep "^.*[\/bin\/false|\/sbin\/nologin]$"') do
    its(:stdout) { should match %r{(\/bin\/false|\/sbin\/nologin)} }
    its(:stderr) { should eq '' }
    its(:exit_status) { should eq 0 }
  end
end

control 'Verify That \'MYSQL_PWD\' Is Not Set In Users\' Profiles' do
  impact 0.7
  desc 'MySQL can read a default database password from an environment variable called MYSQL_PWD.
  Rationale:
  The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
  credentials. Avoiding this may increase assurance that the confidentiality of MySQL
  credentials is preserved.'

  describe command('grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile}') do
    its(:stdout) { should eq '' }
  end
end

control 'Ensure \'datadir\' Has Appropriate Permissions' do
  impact 0.7
  desc 'The data directory is the location of the MySQL databases.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL database.  If someone other than the MySQL user is allowed to
  read files from the data directory he or she might be able to read data from the mysql.user
  table which contains passwords.  Additionally, the ability to create files can lead to denial of
  service, or might otherwise allow someone to gain access to specific data by manually
  creating a file with a view definition.'

  describe directory(data_dir_attribute) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0700' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure \'log_bin_basename\' Files Have Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'
  only_if { !mysql_commands.log_bin_basename.to_s.empty? }

  mysql_commands.log_bin_files.each do |logfile|
    describe file("#{data_dir_attribute}/#{logfile}") do
      it { should be_owned_by 'mysql' }
      it { should exist }
      it { should be_file }
      its('mode') { should cmp '660' }
      its('group') { should eq 'mysql' }
    end
  end
end

control 'Ensure \'log_error\' Has Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'

  describe file(mysql_commands.log_error) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0660' }
    its('group') { should eq 'mysql' }
  end
end

control ' Ensure \'slow_query_log\' Has Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'
  only_if { mysql_commands.slow_query_log == 'ON' }

  describe file(mysql_commands.slow_query_log_file) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0660' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure \'relay_log_basename\' Files Have Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'
  only_if { !mysql_commands.relay_log_basename.to_s.empty? }

  describe file(mysql_commands.relay_log_basename) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    its('mode') { should cmp '660' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure \'general_log_file\' Files Have Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'
  only_if { !mysql_commands.general_log_file.to_s.empty? && mysql_commands.general_log == 'ON' }

  describe file(mysql_commands.general_log_file) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0660' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure SSL Key Files Have Appropriate Permissions' do
  impact 0.7
  desc 'MySQL can operate using a variety of log files, each used for different purposes.  These are
  the binary log, error log, slow query log, relay log, and general log.  Because these are files
  on the host operating system, they are subject to the permissions structure provided by the
  host and may be accessible by users other than the MySQL user.
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.'
  only_if { !mysql_commands.ssl_key.to_s.empty? }

  describe file(mysql_commands.ssl_key) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '400' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure Plugin Directory Has Appropriate Permissions' do
  impact 0.7
  desc 'The plugin directory is the location of the MySQL plugins. Plugins are storage engines or
  user defined functions (UDFs).
  Rationale:
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL database.  If someone can modify plugins then these plugins
  might be loaded when the server starts and the code will get executed.'
  only_if { !mysql_commands.plugin_dir.to_s.empty? }

  describe directory(mysql_commands.plugin_dir) do
    it { should be_owned_by 'mysql' }
    it { should exist }
    it { should be_directory }
    its('mode') { should cmp '0775' }
    its('group') { should eq 'mysql' }
  end
end

control 'Ensure the \'test\' Database Is Not Installed' do
  impact 0.7
  desc 'The default MySQL installation comes with an unused database called test. It is
  recommended that the test database be dropped.
  Rationale:
  The test database can be accessed by all users and can be used to consume system
  resources.  Dropping the test database will reduce the attack surface of the MySQL server'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SHOW DATABASES like 'test';\"") do
    its(:stdout) { should eq '' }
  end
end

control 'Ensure \'allow-suspicious-udfs\' Is Set to \'FALSE\'' do
  impact 0.7
  desc 'This option prevents attaching arbitrary shared library functions as user-defined functions
  by checking for at least one corresponding method named _init, _deinit, _reset, _clear,
  or _add.
  Rationale:
  Preventing shared libraries that do not contain user-defined functions from loading will
  reduce the attack surface of the server.'

  describe file("/etc/mysql-#{service_name}/my.cnf") do
    it { should exist }
    it { should be_file }
    its('content') { should_not match 'allow-suspicious-udfs' }
  end

  describe command('ps aux | grep myslq') do
    its(:stdout) { should_not match 'allow-suspicious-udfs' }
  end
end

control 'Ensure \'local_infile\' Is Disabled' do
  impact 0.7
  desc 'The local_infile parameter dictates whether files located on the MySQL client\'s
  computer can be loaded or selected via LOAD DATA INFILE or SELECT local_file.
  Rationale:
  Disabling local_infile reduces an attacker\'s ability to read sensitive files off the affected
  server via a SQL injection vulnerability'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SHOW VARIABLES WHERE Variable_name = 'local_infile';\" | grep local_infile | awk '{print $2}'") do
    its(:stdout) { should match(/^OFF/) }
  end
end

control 'Ensure \'mysqld\ Is Not Started with \'--skip-grant-tables\'' do
  impact 0.7
  desc 'This option causes mysqld to start without using the privilege system.
  Rationale:
  If this option is used, all clients of the affected server will have unrestricted access to all
  databases.'

  describe parse_config_file("/etc/mysql-#{service_name}/my.cnf") do
    its('mysqld') { should include('skip-grant-tables' => 'FALSE') }
  end
end

control 'Ensure \'--skip-symbolic-links\' Is Enabled' do
  impact 0.7
  desc 'The symbolic-links and skip-symbolic-links options for MySQL determine whether
  symbolic link support is available.  When use of symbolic links are enabled, they have
  different effects depending on the host platform.  When symbolic links are disabled, then
  symbolic links stored in files or entries in tables are not used by the database.
  Rationale:
  Prevents sym links being used for data base files. This is especially important when MySQL
  is executing as root as arbitrary files may be overwritten.  The symbolic-links option might
  allow someone to direct actions by to MySQL server to other files and/or directories.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SHOW variables LIKE 'have_symlink';\" | grep have_symlink | awk '{print $2}'") do
    its(:stdout) { should match(/^DISABLED/) }
  end
end

control 'Ensure the \'daemon_memcached\' Plugin Is Disabled' do
  impact 0.7
  desc 'The InnoDB memcached Plugin allows users to access data stored in InnoDB with the
  memcached protocol.
  Rationale:
  By default the plugin doesn\'t do authentication, which means that anyone with access to
  the TCP/IP port of the plugin can access and modify the data. However, not all data is
  exposed by default.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached';\"") do
    its(:stdout) { should eq '' }
  end
end

control 'Ensure \'secure_file_priv\' Is Not Empty ' do
  impact 0.7
  desc 'The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT local_file.
  It is recommended that this option be set to a file system location that contains only resources
  expected to be loaded by MySQL.
  Rationale:
  Setting secure_file_priv reduces an attacker\'s ability to read sensitive files off the affected server via a SQL injection vulnerability.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>'';") do
    its(:stdout) { should eq '' }
  end

  describe directory(mysql_commands.secure_file_priv) do
    it { should exist }
    it { should be_directory }
  end
end

control 'Ensure \'sql_mode\' Contains \'STRICT_ALL_TABLES\'' do
  impact 0.7
  desc 'When data changing statements are made (i.e. INSERT, UPDATE), MySQL can handle invalid or
  missing values differently depending on whether strict SQL mode is enabled. When strict SQL mode is
  enabled, data may not be truncated or otherwise "adjusted" to make the data changing statement work.
  Rationale:
  Without strict mode the server tries to do proceed with the action when an error might have been a
  more secure choice. For example, by default MySQL will truncate data if it does not fit in a field,
  which can lead to unknown behavior, or be leveraged by an attacker to circumvent data validation.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -e \"SHOW VARIABLES LIKE 'sql_mode';\"") do
    its(:stdout) { should match 'STRICT_ALL_TABLES' }
  end
end

control 'Ensure Only Administrative Users Have Full Database Access' do
  impact 0.7
  desc 'The mysql.user and mysql.db tables list a variety of privileges that can be granted (or denied)
  to MySQL users. Some of the privileges of concern include: Select_priv, Insert_priv,
  Update_priv,Delete_priv,Drop_priv,andsoon. Typically,theseprivileges should not be available to
  every MySQL user and often are reserved for administrative use only.
  Rationale:
  Limiting the accessibility of the \'mysql\' database will protect the confidentiality, integrity, and
  availability of the data housed within MySQL. A user which has direct access to mysql.* might view
  password hashes, change permissions, or alter or destroy information intentionally or unintentionally.'

  describe mysql_commands do
    its(:users1) { should eq '' }
    its(:users2) { should eq '' }
  end
end

control 'Ensure \'file_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The File_priv privilege found in the mysql.user table is used to allow or disallow a user from reading and
  writing files on the server host. Any user with the File_priv right granted has the ability to:
  • Read files from the local file system that are readable by the MySQL server (this includes world-readable files)
  • Write files to the local file system where the MySQL server has write access Rationale:
  The File_priv right allows mysql users to read files from disk and to write files to disk. This may be leveraged
  by an attacker to further compromise MySQL. It should be noted that the MySQL server should not overwrite existing
  files.'

  describe mysql_commands do
    its(:users3) { should eq '' }
  end
end

control 'Ensure \'process_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The PROCESS privilege found in the mysql.user table determines whether a given user can see statement
  execution information for all sessions.
  Rationale:
  The PROCESS privilege allows principals to view currently executing MySQL statements beyond their own,
  including statements used to manage passwords. This may be leveraged by an attacker to compromise MySQL or to
  gain access to potentially sensitive data.'

  describe mysql_commands do
    its(:users4) { should eq '' }
  end
end

control 'Ensure \'super_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features.
  These featuresinclude,CHANGEMASTERTO,KILL,mysqladminkilloption,PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug
  option, logging control, and more.
  Rationale:
  The SUPER privilege allows principals to perform many actions, including view and terminate currently executing
  MySQL statements (including statements used to manage passwords). This privilege also provides the ability to
  configure MySQL, such as enable/disable logging, alter data, disable/enable features. Limiting the accounts that
  have the SUPER privilege reduces the chances that an attacker can exploit these capabilities'

  describe mysql_commands do
    its(:users5) { should eq '' }
  end
end

control 'Ensure \'shutdown_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The SHUTDOWN privilege simply enables use of the shutdown option to the mysqladmin command, which allows
  a user with the SHUTDOWN privilege the ability to shut down the MySQL server.
  Rationale:
  The SHUTDOWN privilege allows principals to shutdown MySQL. This may be leveraged by an attacker to negatively
  impact the availability of MySQL.'

  describe mysql_commands do
    its(:users6) { should eq '' }
  end
end

control 'Ensure \'create_user_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The CREATE USER privilege governs the right of a given user to add or remove users, change existing users\'
  names, or revoke existing users\' privileges.
  Rationale:
  Reducing the number of users granted the CREATE USER right minimizes the number of users able to add/drop users,
  alter existing users\' names, and manipulate existing users\' privileges.'

  describe mysql_commands do
    its(:users7) { should eq '' }
  end
end

control 'Ensure \'grant_priv\' Is Not Set to \'Y\' for Non-Administrative Users' do
  impact 0.7
  desc 'The GRANT OPTION privilege exists in different contexts (mysql.user, mysql.db) for the purpose of governing
  the ability of a privileged user to manipulate the privileges of other users.
  Rationale:
  The GRANT privilege allows a principal to grant other principals additional privileges. This may be used by an
  attacker to compromise MySQL..'

  describe mysql_commands do
    its(:users8) { should eq '' }
    its(:users9) { should eq '' }
  end
end

control 'Ensure \'repl_slave_priv\' Is Not Set to \'Y\' for Non-Slave Users' do
  impact 0.7
  desc 'The REPLICATION SLAVE privilege governs whether a given user (in the context of the master server)
  can request updates that have been made on the master server.
  Rationale:
  The REPLICATION SLAVE privilege allows a principal to fetch binlog files containing all data changing statements
  and/or changes in table data from the master. This may be used by an attacker to read/fetch sensitive data from
  MySQL.'

  describe mysql_commands do
    its(:users10) { should eq '' }
  end
end

control 'Ensure DML/DDL Grants Are Limited to Specific Databases and Users' do
  impact 0.7
  desc 'DML/DDL includes the set of privileges used to modify or create data structures. This includes INSERT,
  SELECT, UPDATE, DELETE, DROP, CREATE, and ALTER privileges.
  Rationale:
  INSERT, SELECT, UPDATE, DELETE, DROP, CREATE, and ALTER are powerful privileges in any database. Such privileges
  should be limited only to those users requiring such rights. By limiting the users with these rights and ensuring
  that they are limited to specific databases, the attack surface of the database is reduced.'

  describe mysql_commands do
    its(:users11) { should eq '' }
  end
end

control 'Ensure \'log_error\' Is Not Empty' do
  impact 0.7
  desc 'The error log contains information about events such as mysqld starting and stopping, when a table needs
  to be checked or repaired, and, depending on the host operating system, stack traces when mysqld fails.
  Rationale:
  Enabling error logging may increase the ability to detect malicious attempts against MySQL, and other critical
  messages, such as if the error log is not enabled then connection error might go unnoticed.'

  describe mysql_commands do
    its(:log_error) { should_not eq '' }
  end
end

control 'Ensure Log Files Are Stored on a Non-System Partition' do
  impact 0.7
  desc 'MySQL log files can be set in the MySQL configuration to exist anywhere on the
  filesystem. It is common practice to ensure that the system filesystem is left uncluttered by applicationlogs. Systemfilesystemsincludetheroot,/var,or/usr.
  Rationale:
  Moving the MySQL logs off the system partition will reduce the probability of denial of service via the exhaustion of available disk space to the operating system'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -N -B -e \"SELECT @@global.log_bin_basename;\"") do
    its(:stdout) { should_not match(%r{\/^\/$}) } # datadir should not be in root '/'
    its(:stdout) { should_not match(%r{^\/(var|user)\/}) } # datadir should not be in a system directory '/'
    its(:stdout) { should match(log_bin) }
    its(:exit_status) { should eq 0 }
  end
end

control 'Ensure \'log_warnings\' Is Set to \'2\'' do
  impact 0.7
  desc 'The log_warnings system variable, enabled by default, provides additional information to the MySQL log. A value of 1 enables logging of warning messages,
  and higher integer values tend to enable more logging.
  NOTE: The variable scope for 5.6.3 and earlier is global and session, but for 5.6.4 and greater its scope is global.
  Rationale:
  This might help to detect malicious behavior by logging communication errors and aborted connections.'

  describe mysql_commands do
    its(:log_warnings) { should eq '2' }
  end
end

control 'Ensure \'log-raw\' Is Set to \'OFF\'' do
  impact 0.7
  desc 'The log-raw MySQL option determines whether passwords are rewritten by the server so as not to appear in log files as plain text.
  If log-raw is enabled, then passwords are written to the various log files (general query log, slow query log, and binary log) in plain text.
  Rationale:
  With raw logging of passwords enabled someone with access to the log files might see plain text passwords.'

  describe parse_config_file("/etc/mysql-#{service_name}/my.cnf") do
    its('mysqld') { should include('log-raw' => 'OFF') }
  end
end

control 'Ensure \'old_passwords\' Is Not Set to \'1\' or \'ON\' ' do
  impact 0.7
  desc 'This variable controls the password hashing method used by the PASSWORD() function and for the IDENTIFIED BY clause of the CREATE USER and GRANT statements.
  Before 5.6.6, the value can be 0 (or OFF), or 1 (or ON). As of 5.6.6, the following value can be one of the following:
  • 0 - authenticate with the mysql_native_password plugin
  • 1 - authenticate with the mysql_old_password plugin
  • 2 - authenticate with the sha256_password plugin
  Rationale:
  The mysql_old_password plugin leverages an algorithm that can be quickly brute forced using an offline dictionary attack. See CVE-2003-1480 for additional details.'

  describe mysql_commands do
    its(:old_passwords) { should_not eq '1' }
    its(:old_passwords) { should_not eq 'ON' }
  end

  describe.one do
    describe mysql_commands do
      its(:old_passwords) { should eq 'OFF' }
    end
    describe mysql_commands do
      its(:old_passwords) { should eq '0' }
    end
    describe mysql_commands do
      its(:old_passwords) { should eq '2' }
    end
  end
end

control 'Ensure \'secure_auth\' Is Set to \'ON\'' do
  impact 0.7
  desc 'This option dictates whether the server will deny connections by clients that attempt to use accounts that have their password stored in the mysql_old_password
  format.
  Rationale:
  Enabling this option will prevent all use of passwords employing the old format (and hence insecure communication over the network).'

  describe mysql_commands do
    its(:secure_auth) { should eq 'ON' }
  end
end

control 'Ensure Passwords Are Not Stored in the Global Configuration' do
  impact 0.7
  desc 'The [client] section of the MySQL configuration file allows setting a user and password to be used. Verify the password option is not used in the global configuration file (my.cnf).
  Rationale:
  The use of the password parameter may negatively impact the confidentiality of the user\'s password.'

  describe parse_config_file("/etc/mysql-#{service_name}/my.cnf") do
    its('client') { should_not include('password') }
  end
end
#
# control 'Ensure \'sql_mode\' Contains \'NO_AUTO_CREATE_USER\'' do
#   impact 0.7
#   desc 'The [client] section of the MySQL configuration file allows setting a user and password to be used. Verify the password option is not used in the global configuration file (my.cnf).
#   Rationale:
#   The use of the password parameter may negatively impact the confidentiality of the user\'s password.'
#
#   describe mysql_commands do
#     its(:global_sql_mode) { should eq 'NO_AUTO_CREATE_USER' }
#     its(:session_sql_mode) { should eq 'NO_AUTO_CREATE_USER' }
#   end
# end

control 'Ensure Passwords Are Set for All MySQL Accounts' do
  impact 0.7
  desc 'Blank passwords allow a user to login without using a password. Rationale:
  Without a password only knowing the username and the list of allowed hosts will allow someone to connect to the server and assume the identity of the user.
  This, in effect, bypasses authentication mechanisms.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -N -B -e \"SELECT User,host FROM mysql.user WHERE (plugin IN('mysql_native_password', 'mysql_old_password') AND (LENGTH(Password) = 0 OR Password IS NULL)) OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);\"") do
    its(:stdout) { should eq '' }
  end
end

control 'Ensure No Users Have Wildcard Hostnames' do
  impact 0.7
  desc 'MySQL can make use of host wildcards when granting permissions to users on specific databases. For example, you may grant a given privilege to \'<user>\'@\'%\'.
  Rationale:
  Avoiding the use of wildcards within hostnames helps control the specific locations from which a given user may connect to and interact with the database.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -N -B -e \"SELECT user, host FROM mysql.user WHERE host = '%';\"") do
    its(:stdout) { should eq '' }
  end
end

control 'Ensure No Anonymous Accounts Exist' do
  impact 0.7
  desc 'Anonymous accounts are users with empty usernames (\'\'). Anonymous accounts have no passwords, so anyone can use them to connect to the MySQL server.
  Rationale:
  Removing anonymous accounts will help ensure that only identified and trusted principals are capable of interacting with MySQL.'

  describe command("mysql -u #{user} -p#{pass} mysql -S /var/run/mysql-#{service_name}/mysqld.sock -N -B -e \"SELECT user,host FROM mysql.user WHERE user = '';\"") do
    its(:stdout) { should eq '' }
  end
end
