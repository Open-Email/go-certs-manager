package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3ClientOptions are the primitive connection parameters for NewS3Client.
// Every field may be zero, in which case the AWS default config chain (env,
// shared config, instance role) supplies it.
type S3ClientOptions struct {
	Region    string
	Endpoint  string // custom S3-compatible endpoint (Cloudflare R2, MinIO, B2)
	AccessKey string
	SecretKey string
	// PathStyle forces path-style addressing. Most S3-compatible services
	// (R2, MinIO, B2) require it when Endpoint is set.
	PathStyle bool
}

// NewS3Client builds an *s3.Client for use with NewS3Backend. It centralizes
// the retryer, static-credentials, and custom-endpoint handling so every
// consumer builds clients the same way. It does NOT validate bucket access —
// callers that need that should use Backend.BucketExists.
func NewS3Client(ctx context.Context, opts S3ClientOptions, logger *slog.Logger) (*s3.Client, error) {
	if logger == nil {
		logger = slog.Default()
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.MaxBackoff = 5 * time.Second
			})
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if opts.Region != "" {
		awsCfg.Region = opts.Region
	}
	if opts.AccessKey != "" && opts.SecretKey != "" {
		awsCfg.Credentials = credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, "")
	}

	if opts.Endpoint != "" {
		logger.Info("s3: using custom S3 endpoint", "endpoint", opts.Endpoint)
		return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(opts.Endpoint)
			o.UsePathStyle = opts.PathStyle
		}), nil
	}
	return s3.NewFromConfig(awsCfg), nil
}
