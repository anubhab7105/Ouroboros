import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type { PageQuery } from '@/types/common';
import type {
  FeatureSchema,
  ModelComparison,
  ModelCurrent,
  ModelEvaluation,
  ModelEvaluationListResponse,
  ModelLimitations,
  ModelMetricsStatus,
  ModelVersion,
  ModelVersionListResponse,
} from '@/types/model';

/** Model monitoring reads. */

export async function fetchModelStatus(): Promise<ModelMetricsStatus> {
  return get<ModelMetricsStatus>(endpoints.model.status());
}

export async function fetchModelCurrent(): Promise<ModelCurrent> {
  return get<ModelCurrent>(endpoints.model.current());
}

export async function fetchModelLimitations(): Promise<ModelLimitations> {
  return get<ModelLimitations>(endpoints.model.limitations());
}

export async function fetchFeatureSchema(): Promise<FeatureSchema> {
  return get<FeatureSchema>(endpoints.model.featureSchema());
}

export async function fetchModelVersions(
  page: PageQuery & {
    model_type?: string;
    is_active?: boolean;
    feature_schema_version?: string;
    version?: string;
  } = {},
): Promise<ModelVersionListResponse> {
  const { model_type, is_active, feature_schema_version, version, ...rest } = page;

  return get<ModelVersionListResponse>(endpoints.model.versions(), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ model_type, is_active, feature_schema_version, version }),
    },
  });
}

export async function fetchModelVersion(id: string): Promise<ModelVersion> {
  return get<ModelVersion>(endpoints.model.version(id));
}

export async function fetchVersionEvaluations(
  id: string,
  page: PageQuery & { split_strategy?: string } = {},
): Promise<ModelEvaluationListResponse> {
  const { split_strategy, ...rest } = page;

  return get<ModelEvaluationListResponse>(endpoints.model.versionEvaluations(id), {
    params: { ...pageParams(rest), ...cleanParams({ split_strategy }) },
  });
}

export async function fetchEvaluation(id: string): Promise<ModelEvaluation> {
  return get<ModelEvaluation>(endpoints.model.evaluation(id));
}

/**
 * Compare two or three model versions.
 *
 * The parameter is repeated — `?version_id=a&version_id=b` — because the
 * endpoint declares it with that alias. axios serialises an array to repeated
 * keys by default, which is what the server expects.
 */
export async function compareModelVersions(versionIds: string[]): Promise<ModelComparison> {
  return get<ModelComparison>(endpoints.model.compare(), {
    params: { version_id: versionIds },
  });
}
