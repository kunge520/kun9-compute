# kun9-compute

一次性算力的投递通道。公开仓库 = GitHub 托管 Linux runner 的分钟数不计数，所以这里用来跑
"进去干完活就把结果带走"的任务，而不是用来挂机或当服务器。

用法：把要跑的脚本提交到 `job/task.sh`（只有 `push` 事件会执行代码，永远不跑 `pull_request`
的 fork 代码），Actions 会执行它并把完整输出提交到 `out/<UTC时间>.txt`（只保留最近 30 份）。

约束（实测，见 out/ 里第一份基线）：每次 run 都是一台全新的 `ubuntu-latest` VM，2 vCPU /
7.75 GiB 内存 / 约 13 GiB 可用磁盘，有 sudo、Docker、Python 3.12、Node 22，无 GPU；VM 用完
即销毁，除 git 之外什么都不留存；单 job 墙钟上限 6 h，免费并发 20 个 job，没有入站端口，
出口 IP 是每次变化的 Azure 数据中心段。

这个仓库**不配置任何 secret**，也不放任何凭据、内网地址或私有主机名——公开仓库里的每一个
字节都应当假设全世界读得。
