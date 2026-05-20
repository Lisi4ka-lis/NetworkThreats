# ── Stage 1: Build ───────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY ["NetworkThreats/NetworkThreats.csproj", "NetworkThreats/"]
RUN dotnet restore "NetworkThreats/NetworkThreats.csproj"

COPY . .
WORKDIR "/src/NetworkThreats"
RUN dotnet publish "NetworkThreats.csproj" -c Release -o /app/publish --no-restore

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

RUN mkdir -p /app/data

COPY --from=build /app/publish .

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080
ENV ConnectionStrings__DefaultConnection="Data Source=/app/data/networkthreats.db"

EXPOSE 8080

ENTRYPOINT ["dotnet", "NetworkThreats.dll"]
