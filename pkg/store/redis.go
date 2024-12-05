package store

import (
	"context"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

func rlog() *slog.Logger {
	return slog.With("component", "store.Redis")
}

type Redis struct {
	log    *slog.Logger
	ctx    context.Context
	client *redis.Client
}

func NewRedis(ctx context.Context, address, user, password string) *Redis {
	return &Redis{
		log: rlog(),
		ctx: ctx,
		client: redis.NewClient(&redis.Options{
			Addr:     address,
			Username: user,
			Password: password,
		}),
	}
}

func (rd *Redis) PipelineStage(in <-chan DNSEntry) {
	defer rd.client.Close()
	for entry := range in {
		for _, ip := range entry.IPs {
			// TODO: store IPv4 also with its IPv6 representation
			rd.append(ip, entry.HostName)
		}
	}
}

func (rd *Redis) GetHostnames(ip string) []string {
	if res, err := rd.client.SMembers(rd.ctx, ip).Result(); err != nil {
		rd.log.Error("retrieving hostnames from redis", "error", err)
		return nil
	} else {
		return res
	}
}

func (rd *Redis) append(ip string, name string) {
	if _, err := rd.client.SAdd(rd.ctx, ip, name).Result(); err != nil {
		rd.log.Error("appending hostname to redis", "error", err)
	}
}
