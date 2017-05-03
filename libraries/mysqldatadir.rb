class MysqlDatadir < Inspec.resource(1)
  name 'mysql_commands'
  attr_reader :datadir
  attr_reader :log_error
  attr_reader :slow_query_log_file
  attr_reader :slow_query_log
  attr_reader :log_warnings
  attr_reader :log_bin_basename
  attr_reader :log_bin_files
  attr_reader :relay_log_basename
  attr_reader :general_log_file
  attr_reader :general_log
  attr_reader :ssl_key
  attr_reader :plugin_dir
  attr_reader :db_test
  attr_reader :secure_auth
  attr_reader :old_passwords
  attr_reader :secure_file_priv
  attr_reader :global_sql_mode
  attr_reader :session_sql_mode
  attr_reader :users1
  attr_reader :users2
  attr_reader :users3
  attr_reader :users4
  attr_reader :users5
  attr_reader :users6
  attr_reader :users7
  attr_reader :users8
  attr_reader :users9
  attr_reader :users10
  attr_reader :users11
  @pass = ''
  @user = ''
  @db_user = ''
  def initialize
    node = Hashie::Mash.new(inspec.json('/tmp/node.json').params)
    @db_user = node['db']['username']
    @pass = node['db']['server_root_password']
    @user = node['db']['root_user']
    @datadir = inspec_show_variables_command('datadir')
    @log_error = inspec_show_variables_command('log_error')
    @slow_query_log_file = inspec_show_variables_command('slow_query_log_file')
    @slow_query_log = inspec_show_variables_command('slow_query_log')
    @log_bin_basename = inspec_show_variables_command('log_bin_basename')
    @log_bin_files = inspec.command("ls #{@datadir} | egrep ^mysql-bin\.").stdout.split("\n")
    @log_warnings = inspec_show_variables_command_not_empty('log_warnings')
    @relay_log_basename = inspec_show_variables_command('relay_log_basename')
    @general_log = inspec_show_variables_command('general_log')
    @general_log_file = inspec_show_variables_command('general_log_file')
    @ssl_key = inspec_show_variables_command('ssl_key')
    @plugin_dir = inspec_show_variables_command('plugin_dir')
    @secure_auth = inspec_show_variables_command('secure_auth')
    @db_test = inspec_show_databases_command('test')
    @secure_file_priv = inspec_show_variables_command_not_empty('secure_file_priv')
    @old_passwords = inspec_show_variables_command('old_passwords')
    @global_sql_mode = inspec.command("#{mysql_connect} -N -B -e \"SELECT @@global.sql_mode;\"").stdout.strip!
    @session_sql_mode = inspec.command("#{mysql_connect} -N -B -e \"SELECT @@session.sql_mode;\"").stdout.strip!
    @users1 = users_command("select user FROM mysql.user WHERE (Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y');")
    @users2 = users_command("select user FROM mysql.db WHERE db = 'mysql' AND ((Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y'));")
    @users3 = users_command("select user from mysql.user where File_priv = 'Y';")
    @users4 = users_command("select user from mysql.user where Process_priv = 'Y';")
    @users5 = users_command("select user from mysql.user where Super_priv = 'Y';")
    @users6 = users_command("select user FROM mysql.user WHERE Shutdown_priv = 'Y';")
    @users7 = users_command("SELECT user FROM mysql.user WHERE Create_user_priv = 'Y';")
    @users8 = users_command("SELECT user FROM mysql.user WHERE Grant_priv = 'Y';")
    @users9 = users_command("SELECT user FROM mysql.db WHERE Grant_priv = 'Y';")
    @users10 = users_command("SELECT user FROM mysql.user WHERE Repl_slave_priv = 'Y';")
    @users11 = users_command("SELECT User FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y';")
  end

  def mysql_connect
    "mysql -u #{@user} -p#{@pass} mysql -S /var/run/mysql-default/mysqld.sock"
  end

  def inspec_show_variables_command_not_empty(variable)
    inspec.command("#{mysql_connect} -N -B -e \"SHOW GLOBAL VARIABLES WHERE Variable_name = '#{variable}' AND Value<>'';\" | awk '{print $2}'").stdout.strip!
  end

  def inspec_show_variables_command(variable)
    inspec.command("#{mysql_connect} -N -B -e \"show variables like '#{variable}';\" | awk '{print $2}'").stdout.strip!
  end

  def inspec_show_databases_command(db)
    inspec.command("#{mysql_connect} -e \"SHOW DATABASES like '#{db}';\"").stdout.strip!
  end

  def users_command(query)
    stdout = inspec.command("#{mysql_connect} -N -B -e \"#{query}\"").stdout.strip!
    adimn_users = [@db_user, @user]
    return '' if stdout.to_s.empty?
    stdout.split("\n").delete_if { |x| adimn_users.include?(x) }.join(',')
  end
end
