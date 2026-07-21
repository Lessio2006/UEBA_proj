import torch
import torch.nn as nn
import numpy as np
import pandas as pd


class VariationalAE(nn.Module):
  def __init__(self, input_dim=30, hidden_dim=60, latent_dim=6):
    super().__init__()

    self.encoder = nn.Sequential(
        nn.Linear(input_dim, hidden_dim),
        nn.ReLU(),
        nn.Linear(hidden_dim, hidden_dim // 2),
        nn.ReLU(),
        nn.Linear(hidden_dim // 2, hidden_dim // 4),
        nn.ReLU()
    )

    self.fc_mu = nn.Linear(hidden_dim // 4, latent_dim)
    self.fc_log_var = nn.Linear(hidden_dim // 4, latent_dim)

    self.decoder = nn.Sequential(
        nn.Linear(latent_dim, hidden_dim),
        nn.ReLU(),
        nn.Linear(hidden_dim, hidden_dim),
        nn.ReLU(),
        nn.Linear(hidden_dim, input_dim),  # Output layer, reconstructing input_dim features

    )

    self.input_dim = input_dim
    self.hidden_dim = hidden_dim
    self.latent_dim = latent_dim

  @staticmethod
  def reparameterize(mu, log_var):
    """
    :param mu: mean from the encoder's latent space
    :param log_var: log variance from the encoder's latent space
    :return: A sample from the latent distribution
    """
    std = torch.exp(0.5 * log_var)
    eps = torch.randn_like(std)
    sample = mu + (eps * std)
    return sample


  def encode(self, x):
    h = self.encoder(x) # Pass input through the sequential encoder layers
    mu = self.fc_mu(h)
    log_var = self.fc_log_var(h)
    return mu, log_var

  def decode(self, z):
    reconstruction = self.decoder(z) # Pass latent sample through the sequential decoder layers
    return reconstruction

  def forward(self, x):
    mu, log_var = self.encode(x)
    z = self.reparameterize(mu, log_var)
    reconstruction = self.decode(z)    # Decode the latent sample to reconstruct the input
    return reconstruction, mu, log_var


def load_bundle(path, device="cpu"):
    checkpoint = torch.load(
        path,
        map_location=device,
        weights_only=False
    )

    model = VariationalAE(
        input_dim=checkpoint["input_dim"],
        hidden_dim=checkpoint["hidden_dim"],
        latent_dim=checkpoint["latent_dim"]
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(device)
    model.eval()

    return model, checkpoint


def preprocess(df: pd.DataFrame, bundle: dict) -> np.ndarray:

    x = df.copy()

    x = x.drop(
        columns=[
            "timestamp",
            "weekday_sin",
            "weekday_cos",
            "hour_sin",
            "hour_cos",
        ],
        errors="ignore"
    )

    # Точные колонки из обучающего Colab
    for col in bundle["log_columns"]:
        if col not in x.columns:
            raise ValueError(
                f"Отсутствует признак: {col}"
            )

        x[col] = np.log1p(x[col])

    feature_names = bundle["feature_names"]

    missing = [
        col for col in feature_names
        if col not in x.columns
    ]

    if missing:
        raise ValueError(
            f"Отсутствуют признаки: {missing}"
        )

    # Точный порядок из обучения
    x = x[feature_names]

    values = x.to_numpy(dtype=np.float32)

    mean = (
        bundle["scaler_mean"]
        .cpu()
        .numpy()
    )

    scale = (
        bundle["scaler_scale"]
        .cpu()
        .numpy()
    )

    x_scaled = (values - mean) / scale

    return x_scaled.astype(np.float32)

def predict_anomaly(
    df: pd.DataFrame,
    model: VariationalAE,
    bundle: dict,
    device="cpu"
) -> pd.DataFrame:

    x_scaled = preprocess(
        df,
        bundle
    )

    feature_names = bundle["feature_names"]

    debug_scaled = pd.DataFrame(
        x_scaled,
        columns=feature_names
    )

    print(
        debug_scaled
        .abs()
        .mean()
        .sort_values(ascending=False)
        .head(10)
    )

    x_tensor = torch.from_numpy(
        x_scaled
    ).to(device)

    with torch.no_grad():
        mu, _ = model.encode(x_tensor)
        reconstruction = model.decode(mu)

        scores = torch.mean(
            (x_tensor - reconstruction) ** 2,
            dim=1
        )

    scores = scores.cpu().numpy()
    threshold = float(bundle["threshold"])

    result = df.copy()
    result["anomaly_score"] = scores
    result["is_anomaly"] = scores > threshold

    return result


if __name__ == "__main__":
    model, bundle = load_bundle("/models/ueba_bundle.pt")

    df = pd.read_csv("example_path.csv")

    result = predict_anomaly(df, model, bundle)

    print(
        result[
            [
                "timestamp",
                "anomaly_score",
                "is_anomaly"
            ]
        ]
    )

