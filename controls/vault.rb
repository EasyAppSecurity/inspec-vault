# encoding: utf-8
# frozen_string_literal: true

# Copyright 2018, Martez Reed
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Martez Reed

title 'Vault Secure Configuration'

vault_executable = attribute(
  'vault_executable',
  default: '/usr/local/bin/vault',
  description: 'The path on the system where the Vault executable is located'
)

vault_service = attribute(
  'vault_service',
  default: 'vault',
  description: 'The name of the vault service'
)

vault_service_path = attribute(
  'vault_service_path',
  default: '/etc/systemd/system/vault.service',
  description: 'The path on the system where the Vault service configuration file is located'
)

vault_dir = attribute(
  'vault_dir',
  default: '/opt/vault',
  description: 'The system path for the vault installation'
)

vault_user = attribute(
  'vault_user',
  default: 'vault',
  description: 'The system user account that the vault service runs as'
)

vault_tlscert = attribute(
  'vault_tlscert',
  description: 'Path to TLS certificate file',
  default: '/opt/vault/ssl/server_cert.pem'
)

vault_tlskey = attribute(
  'vault_tlskey',
  description: 'Path to TLS key file',
  default: '/opt/vaul/ssl/server_key.pem'
)

vault_config = attribute(
  'vault_config',
  description: 'Path to Vault configuration file',
  default: '/etc/vault/config.hcl'
)

# check if vault exists
only_if do
  command('vault').exist?
end

control 'vault-1.1' do
  impact 1.0
  title 'Verify Vault status attributes'
  desc 'Verify Vault status attributes'

  describe json({ command: 'vault status -format json' }) do
	  its('sealed') { should eq false }
	  its('version') { should cmp >= '1.4.2' }
	  its('storage_type') { should_not eq 'inmem' }
	  its('n') { should cmp >= '3' }
	  its('t') { should cmp >= '2' }
  end

end

control 'vault-1.2' do
  impact 1.0
  title 'Audit Vault executable'
  desc 'Audit all Vault executable activities'

  only_if { os.linux? }
  rule = '-w ' + vault_executable + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.3' do
  impact 1.0
  title 'Verify that vault configuration directory permissions are set to 640 or more restrictive'
  desc 'Verify that vault configuration directory permissions are set to 640 or more restrictive'

  describe directory(vault_dir) do
	it { should exist }
    its('owner') { should eq vault_user }
    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'vault-1.4' do
  impact 1.0
  title 'Audit Vault files and directories'
  desc 'Audit the Vault files and directories'

  only_if { os.linux? }
  rule = '-w ' + vault_dir + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.5' do
  impact 1.0
  title 'Audit Vault service configuration'
  desc 'Audit Vault service configuration file'

  only_if { os.linux? }
  rule = '-w ' + vault_service_path + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.6' do
  impact 1.0
  title 'Ensure that the vault service is running'
  desc 'Ensure that the Vault systemd service is running and enabled'

  describe service(vault_service) do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'vault-1.7' do
  impact 1.0
  title 'Ensure Vault is not running as root'
  desc 'Ensure that the Vault service is not being run as root'

  describe processes('vault') do
    its('users') { should_not eq ['root'] }
  end
end

control 'vault-1.8' do
  impact 1.0
  title 'Ensure swap is disabled on the system'
  desc 'Ensure that swap is disabled on the system to prevent secrets from being written to disk'

  describe command('swapon -s | grep -v Filename') do
    its('exit_status') { should eq 1 }
  end
end

control 'vault-1.9' do
  impact 1.0
  title 'Verify that vault.service file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'vault.service\' file permissions are correctly set to \'644\' or more restrictive.'

  describe file(vault_service_path) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.10' do
  impact 1.0
  title 'Verify that Vault certificate file permissions are set to 400'
  desc 'Verify that Vault certificate file permissions are set to 400'

  describe file(vault_tlskey) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should_not be_writable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.11' do
  impact 1.0
  title 'Verify that Vault certificate file permissions are set to 400'
  desc 'Verify that Vault certificate file permissions are set to 400'

  describe file(vault_tlscert) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should_not be_writable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.12' do
  impact 0.5
  title 'Ensure Core Dumps are turned off'
  desc 'A user or administrator that can force a core dump and has access to the resulting file can potentially access Vault encryption keys'

  describe command('ulimit -c') do
    its(:stdout) { should eq '0' }
  end
end

control 'vault-1.13' do
  impact 1.0
  title 'Ensure mlock is not disabled'
  desc 'mlock prevents memory from being swapped to disk. Disabling mlock is not recommended in production, but is fine for local development and testing.'
  
  only_if do
    file(vault_config.to_s).exist?
  end
  
  mlock_disable_option = 'egrep -E \'^(disable_mlock)(\s+)=(\s+)(true)$\' ' + vault_config.to_s
  describe command(mlock_disable_option) do
    its(:stdout) { should be_empty }
  end

end
