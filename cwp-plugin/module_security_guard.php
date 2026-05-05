<?php
/**
 * Interface Gráfica do Security Guard para o Control Web Panel (CWP)
 * 
 * Este arquivo atua como o Controller (Backend) e a View (Frontend) para 
 * gerenciar as listas de permissões do módulo security_guard.
 */

// Inclui a classe principal
require_once __DIR__ . '/SecurityGuardPlugin.php';

// Inicializa o gerenciador
$plugin = new SecurityGuardPlugin();

// Identifica o usuário logado (exemplo básico, ajuste conforme as sessões do seu painel)
$adminUser = isset($_SESSION['id']) ? $_SESSION['id'] : 'admin';

// Mensagens de feedback
$mensagem = '';
$tipoMensagem = 'success';

// Processamento de formulários (Ações de adicionar/remover)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $acao = $_POST['action'] ?? '';
    
    try {
        switch ($acao) {
            case 'add_command':
                $comando = trim($_POST['comando'] ?? '');
                $obs = trim($_POST['obs'] ?? 'Added via Panel');
                if (!empty($comando)) {
                    $plugin->addCommand($comando, $adminUser, $obs);
                    $mensagem = "Command '$comando' added successfully!";
                }
                break;
                
            case 'remove_command':
                $comando = trim($_POST['comando'] ?? '');
                if (!empty($comando)) {
                    $plugin->removeCommand($comando, $adminUser);
                    $mensagem = "Command '$comando' removed successfully!";
                }
                break;

            case 'add_file':
                $arquivo = trim($_POST['arquivo'] ?? '');
                $obs = trim($_POST['obs'] ?? 'Added from Panel');
                if (!empty($arquivo)) {
                    $plugin->addFile($arquivo, $adminUser, $obs);
                    $mensagem = "File/Directory '$arquivo' added successfully!";
                }
                break;
                
            case 'remove_file':
                $arquivo = trim($_POST['arquivo'] ?? '');
                if (!empty($arquivo)) {
                    $plugin->removeFile($arquivo, $adminUser);
                    $mensagem = "File '$arquivo' removed successfully!";
                }
                break;

            case 'add_network':
                $tipo = trim($_POST['tipo'] ?? 'domain');
                $valor = trim($_POST['valor'] ?? '');
                $obs = trim($_POST['obs'] ?? 'Added via Panel');
                if (!empty($valor)) {
                    $plugin->addNetwork($tipo, $valor, $adminUser, $obs);
                    $mensagem = "Network rule '$valor' added successfully!";
                }
                break;
                
            case 'remove_network':
                $tipo = trim($_POST['tipo'] ?? 'domain');
                $valor = trim($_POST['valor'] ?? '');
                if (!empty($valor)) {
                    $plugin->removeNetwork($tipo, $valor, $adminUser);
                    $mensagem = "Network rule '$valor' removed successfully!";
                }
                break;
        }
    } catch (Exception $e) {
        $mensagem = "Error: " . $e->getMessage();
        $tipoMensagem = 'danger';
    }
}

// Carrega as listas atuais para exibição
$comandos = $plugin->listCommands();
$arquivos = $plugin->listFiles();
$redes = $plugin->listNetwork();
?>

<!-- ==========================================
     FRONTEND (HTML / CSS / JS)
     Usando Bootstrap (padrão em painéis CWP)
=========================================== -->
<div class="container-fluid" style="margin-top: 20px;">
    
    <h2>🛡️ PHP Security Guard - Manager</h2>
    <p class="text-muted">Manage security rules and whitelists for the PHP Security Guard extension.</p>
    
    <?php if ($mensagem): ?>
        <div class="alert alert-<?php echo $tipoMensagem; ?> alert-dismissible fade in" role="alert">
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
            </button>
            <?php echo htmlspecialchars($mensagem); ?>
        </div>
    <?php endif; ?>

    <!-- Abas de Navegação -->
    <ul class="nav nav-tabs" role="tablist">
        <li role="presentation" class="active"><a href="#commands" aria-controls="commands" role="tab" data-toggle="tab">Commands</a></li>
        <li role="presentation"><a href="#files" aria-controls="files" role="tab" data-toggle="tab">Files</a></li>
        <li role="presentation"><a href="#network" aria-controls="network" role="tab" data-toggle="tab">Network/Domains</a></li>
    </ul>

    <!-- Conteúdo das Abas -->
    <div class="tab-content" style="padding-top: 20px;">

        <!-- ABA COMANDOS -->
        <div role="tabpanel" class="tab-pane active" id="commands">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <strong>Add New Allowed Command</strong>
                </div>
                <div class="panel-body">
                    <form method="POST" class="form-inline">
                        <input type="hidden" name="action" value="add_command">
                        <div class="form-group">
                            <label>Binary Path:</label>
                            <input type="text" name="comando" class="form-control" placeholder="e.g. /usr/bin/git" required style="width: 250px;">
                        </div>
                        <div class="form-group">
                            <label>Note:</label>
                            <input type="text" name="obs" class="form-control" placeholder="Reason for allowance" style="width: 250px;">
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="fa fa-plus"></i> Add</button>
                    </form>
                </div>
            </div>

            <table class="table table-striped table-bordered table-hover">
                <thead>
                    <tr>
                        <th>Binary</th>
                        <th>Added On</th>
                        <th>Admin User</th>
                        <th>Note</th>
                        <th width="100">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($comandos as $c): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($c['value']); ?></code></td>
                        <td><?php echo htmlspecialchars($c['date']); ?></td>
                        <td><?php echo htmlspecialchars($c['user']); ?></td>
                        <td><?php echo htmlspecialchars($c['obs'] ?? '-'); ?></td>
                        <td>
                            <form method="POST" style="margin:0;">
                                <input type="hidden" name="action" value="remove_command">
                                <input type="hidden" name="comando" value="<?php echo htmlspecialchars($c['value']); ?>">
                                <button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('Are you sure?');">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- ABA ARQUIVOS -->
        <div role="tabpanel" class="tab-pane" id="files">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <strong>Add Allowed File/Directory</strong>
                </div>
                <div class="panel-body">
                    <form method="POST" class="form-inline">
                        <input type="hidden" name="action" value="add_file">
                        <div class="form-group">
                            <label>Path:</label>
                            <input type="text" name="arquivo" class="form-control" placeholder="e.g. /etc/passwd or /var/www/" required style="width: 250px;">
                        </div>
                        <div class="form-group">
                            <label>Note:</label>
                            <input type="text" name="obs" class="form-control" placeholder="Reason for allowance" style="width: 250px;">
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="fa fa-plus"></i> Add</button>
                    </form>
                </div>
            </div>

            <table class="table table-striped table-bordered table-hover">
                <thead>
                    <tr>
                        <th>File/Directory</th>
                        <th>Added On</th>
                        <th>Admin User</th>
                        <th>Note</th>
                        <th width="100">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($arquivos as $f): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($f['value']); ?></code></td>
                        <td><?php echo htmlspecialchars($f['date']); ?></td>
                        <td><?php echo htmlspecialchars($f['user']); ?></td>
                        <td><?php echo htmlspecialchars($f['obs'] ?? '-'); ?></td>
                        <td>
                            <form method="POST" style="margin:0;">
                                <input type="hidden" name="action" value="remove_file">
                                <input type="hidden" name="arquivo" value="<?php echo htmlspecialchars($f['value']); ?>">
                                <button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('Are you sure?');">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- ABA REDE -->
        <div role="tabpanel" class="tab-pane" id="network">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <strong>Add Network Rule</strong>
                </div>
                <div class="panel-body">
                    <form method="POST" class="form-inline">
                        <input type="hidden" name="action" value="add_network">
                        <div class="form-group">
                            <label>Type:</label>
                            <select name="tipo" class="form-control">
                                <option value="domain">Domain (e.g. api.github.com)</option>
                                <option value="url">URL (e.g. https://api.stripe.com)</option>
                                <option value="ip">Fixed IP (e.g. 8.8.8.8)</option>
                                <option value="cidr">IP Range (CIDR e.g. 10.0.0.0/8)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Value:</label>
                            <input type="text" name="valor" class="form-control" required style="width: 250px;">
                        </div>
                        <div class="form-group">
                            <label>Note:</label>
                            <input type="text" name="obs" class="form-control" placeholder="Reason" style="width: 200px;">
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="fa fa-plus"></i> Add</button>
                    </form>
                </div>
            </div>

            <table class="table table-striped table-bordered table-hover">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Target (Value)</th>
                        <th>Added On</th>
                        <th>Admin User</th>
                        <th>Note</th>
                        <th width="100">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($redes as $n): ?>
                    <tr>
                        <td><span class="label label-info"><?php echo htmlspecialchars(strtoupper($n['type'])); ?></span></td>
                        <td><code><?php echo htmlspecialchars($n['value']); ?></code></td>
                        <td><?php echo htmlspecialchars($n['date']); ?></td>
                        <td><?php echo htmlspecialchars($n['user']); ?></td>
                        <td><?php echo htmlspecialchars($n['obs'] ?? '-'); ?></td>
                        <td>
                            <form method="POST" style="margin:0;">
                                <input type="hidden" name="action" value="remove_network">
                                <input type="hidden" name="tipo" value="<?php echo htmlspecialchars($n['type']); ?>">
                                <input type="hidden" name="valor" value="<?php echo htmlspecialchars($n['value']); ?>">
                                <button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('Are you sure?');">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
</div>

<script>
// Mantém a aba ativa após reload
document.addEventListener('DOMContentLoaded', function() {
    var activeTab = localStorage.getItem('sg_active_tab');
    if (activeTab) {
        $('.nav-tabs a[href="' + activeTab + '"]').tab('show');
    }
    $('.nav-tabs a').on('shown.bs.tab', function (e) {
        localStorage.setItem('sg_active_tab', $(e.target).attr('href'));
    });
});
</script>
