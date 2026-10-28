"""Small packed GRU classifier and sequence autoencoder."""
from ml.common import require_torch

torch = require_torch()
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence


class GRUModel(nn.Module):
    def __init__(self, input_size, hidden_size=32, dropout=0.1, mode="benign_autoencoder"):
        super().__init__()
        if mode not in ("benign_autoencoder", "supervised"):
            raise ValueError("Unknown model mode")
        self.mode = mode
        self.encoder = nn.GRU(input_size, hidden_size, num_layers=1, batch_first=True)
        self.dropout = nn.Dropout(dropout)
        if mode == "supervised":
            self.head = nn.Sequential(nn.Linear(hidden_size, 16), nn.ReLU(), nn.Dropout(dropout), nn.Linear(16, 1))
        else:
            self.decoder = nn.GRU(input_size, hidden_size, num_layers=1, batch_first=True)
            self.head = nn.Linear(hidden_size, input_size)

    def forward(self, x, lengths):
        packed = pack_padded_sequence(x, lengths.detach().cpu(), batch_first=True, enforce_sorted=False)
        _, hidden = self.encoder(packed)
        hidden = self.dropout(hidden)
        if self.mode == "supervised":
            return self.head(hidden[-1]).squeeze(-1)
        # Zero-input decoder: cannot copy each input timestep by teacher forcing.
        decoded, _ = self.decoder(torch.zeros_like(x), hidden)
        return self.head(decoded)


def reconstruction_errors(prediction, target, lengths):
    mask = torch.arange(target.shape[1], device=target.device)[None, :] < lengths[:, None]
    squared = (prediction - target).square().mean(dim=-1)
    return (squared * mask).sum(dim=1) / lengths
